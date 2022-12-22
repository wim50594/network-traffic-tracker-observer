import os
import requests
import adblock
import config
import pandas as pd
from pathlib import Path
from tqdm import tqdm
from utils.utility import (
    write_json,
    load_json,
    init_logger,
    list_dir,
    list_files,
    is_tool,
    sha3,
    write_file,
)
from concurrent.futures import ProcessPoolExecutor
from resource import resource
from typing import List, Tuple
from tld import get_fld
from urllib.parse import urlparse

conf = config.load_config()
logs = init_logger("Preprocessor", conf, verbose=True)


def check_requirements():
    requirements = ["tshark"]
    for req in requirements:
        if not is_tool(req):
            logs.critical(f"Install required packages: {req}")
            return False
    return True


def pcap_to_json(dir_path):
    ssl = dir_path.parent / conf["crawler"]["ssl"]
    pcap = dir_path / conf["crawler"].get("pcap", "tcpdump.pcap")
    if not ssl.is_file() or not pcap.is_file():
        logs.error(f"FileNotFound at {ssl} or {pcap}")
        return

    capture = dir_path / conf["preprocess"].get("capture", "capture.json")
    logs.debug(f"Convert {pcap}: -> {capture}")

    os.system(
        f'tshark -r "{pcap}" -T json -o "tls.keylog_file:{ssl}" --no-duplicate-keys > "{capture}"'
    )


def has_layer(obj, key):
    return (
        "_source" in obj
        and "layers" in obj["_source"]
        and key in obj["_source"]["layers"]
    )


def get_layer(obj, key):
    if has_layer(obj, key):
        return obj["_source"]["layers"][key]
    else:
        return None


def get_http2_url(header):
    return f"{header[':scheme']}://{header[':authority']}{header[':path']}"


def get_resources(data, website_call, study_name) -> Tuple[List[resource], str]:
    resources = {}
    first_party = website_call
    is_final_fp = False
    for packet in data:
        frame = get_layer(packet, "frame")
        frame_nr = int(frame["frame.number"])
        if "http" not in frame["frame.protocols"]:
            continue

        tcp = get_layer(packet, "tcp")
        if not tcp:
            continue

        ip_addr = next(
            (ip for ip in get_attr(packet, "ip.addr")
             if not ip.startswith("172.17")),
            None,
        )
        tcp_id = tcp["tcp.stream"]
        connection_id = sha3(str((website_call, study_name, tcp_id)))

        if has_layer(packet, "http2"):
            # HTTP2
            http2s = get_layer(packet, "http2")
            if not isinstance(http2s, list):
                http2s = [http2s]
            for http2 in http2s:
                if not "http2.stream" in http2:
                    continue
                http2_streams = http2["http2.stream"]
                if not isinstance(http2_streams, list):
                    http2_streams = [http2_streams]

                for http2_stream in http2_streams:
                    if not "http2.streamid" in http2_stream:
                        # Magic packet for signaling
                        continue
                    http2_id = http2_stream["http2.streamid"]
                    resource_id = sha3(
                        str((website_call, study_name, tcp_id, http2_id)))

                    if "0" == http2_stream["http2.type"]:
                        # HTTP2 Data
                        if not resource_id in resources:
                            # skip because missing starting point
                            logs.warning(
                                f"Skip because missing starting point context={website_call}, framenr={frame_nr}, httpstream={http2_id}")
                            continue
                        resources[resource_id].add_packet(frame_nr)

                        if http2_stream["http2.flags_tree"]["http2.flags.end_stream"] == "1":
                            # isEndStream
                            resources[resource_id].end_stream = frame_nr

                    elif "1" == http2_stream["http2.type"] or "5" == http2_stream["http2.type"]:
                        # HTTP2 Header or Server Push (Promise)
                        if "http2.header" not in http2_stream:
                            continue

                        headers = {
                            header["http2.header.name"]: header["http2.header.value"]
                            for header in http2_stream["http2.header"]
                        }
                        if ":method" in headers:
                            # HTTP request or Server Push
                            if "http2.push_promise.promised_stream_id" in http2_stream:
                                http2_pushid = http2_stream["http2.push_promise.promised_stream_id"]
                                resource_id = sha3(
                                    str((website_call, study_name, tcp_id, http2_pushid)))

                            if resource_id in resources:
                                logs.critical(
                                    f"Skip because resource already exists context={website_call}, framenr={frame_nr}, httpstream={http2_id}")
                                continue
                            url = get_http2_url(headers)
                            r = resource(resource_id, url, connection_id, ip_addr,
                                         "http2", headers[":method"], website_call, frame_nr)
                            resources[resource_id] = r
                        else:
                            # HTTP response
                            if not resource_id in resources:
                                # skip because missing starting point
                                logs.warning(
                                    f"Skip because missing starting point context={website_call}, framenr={frame_nr}, httpstream={http2_id}")
                                continue
                            resources[resource_id].add_packet(frame_nr)

                            is_fp = urlparse(
                                resources[resource_id].url).netloc == first_party

                            if not is_final_fp and is_fp:
                                if "location" in headers:
                                    location = urlparse(
                                        headers["location"]).netloc
                                    if location:
                                        first_party = location

                                elif headers[":status"].startswith("2"):
                                    is_final_fp = True

                            if http2_stream["http2.flags_tree"]["http2.flags.eh"] == "1":
                                # isEndStream
                                resources[resource_id].end_header = frame_nr

                            if "content-type" in headers:
                                resources[resource_id].content = headers["content-type"]

        elif has_layer(packet, "http"):
            # HTTP
            http = get_layer(packet, "http")
            if not "http.request_in" in http:
                continue
            start = int(http["http.request_in"])
            start_packet = get_layer(data[start - 1], "http")
            method = next(iter(start_packet.values()))["http.request.method"]
            resource_id = sha3(str((website_call, study_name, tcp_id, start)))
            url = http["http.response_for.uri"]
            content = http["http.content_type"] if "http.content_type" in http else None
            r = resource(resource_id, url, connection_id, ip_addr, "http",
                         method, website_call, start, end_header=frame_nr, content=content)
            r.add_packet(frame_nr)
            resources[resource_id] = r

            is_fp = urlparse(url).netloc == first_party
            if not is_final_fp and is_fp:
                if "http.location" in http:
                    location = urlparse(http["http.location"]).netloc
                    if location:
                        first_party = location

                elif next(iter(http.values()))["http.response.code"].startswith("2"):
                    is_final_fp = True

    return [v for _, v in resources.items()], first_party


def add_tcp(data, resources):
    for resource in resources:
        tmp_packets = []
        for packet_nr in resource.packets:
            # packet_nr starts with 1
            tcp = get_layer(data[packet_nr - 1], "tcp.segments")
            if not tcp:
                continue
            for tcp_nr in tcp["tcp.segment"]:
                tmp_packets.append(int(tcp_nr))

        resource.add_packets(tmp_packets)
        resource.packets.sort()


def get_ip_first(resources, first_party):
    for resource in resources:
        if urlparse(resource.url).netloc == first_party:
            return resource.ip
    return None


def create_resources(data, website, study_name) -> List[resource]:
    resources, first_party = get_resources(data, website, study_name)
    ip_first = get_ip_first(resources, first_party)
    context = get_fld(first_party, fix_protocol=True)

    if get_fld(website, fix_protocol=True).split(".")[0] not in context:
        logs.critical(
            f"Different context called website={website} context={context}")

    for resource in resources:
        resource.first_party = first_party
        resource.context = context
        resource.ip_context = ip_first
        resource.is_tp = resource.is_thirdparty()
        resource.study_name = study_name

    add_tcp(data, resources)
    return resources


def set_tracker(data, resources):
    for resource in resources:
        if not resource.is_tracker:
            continue
        for packet_nr in resource.packets:
            data[packet_nr - 1]["is_tracker"] = True


def load_adblock():
    raw_rules = []
    save_filterlist = conf["preprocess"].getboolean("save_filterlist", True)
    filterlists = list_files(Path("lists/block"))

    if save_filterlist and len(filterlists) > 0:
        logs.debug(f"Loading filterlist from {filterlists}")
        for filterlist in filterlists:
            logs.debug(f"Reading filterset {filterlist}")
            with open(filterlist) as f:
                text_rules = f.read()
            raw_rules.extend(text_rules.splitlines())
    else:
        filterlist_origin = eval(conf["preprocess"].get("filterlist", "[]"))
        logs.debug(f"Create new filterlist of {filterlist_origin}")
        if not isinstance(filterlist_origin, list):
            filterlist_origin = [filterlist_origin]

        for origin in filterlist_origin:
            if origin.startswith("http"):
                try:
                    text_rules = requests.get(origin).text
                    if save_filterlist:
                        list_path = (
                            Path("lists/block") /
                            urlparse(origin).path.split("/")[-1]
                        )
                        write_file(list_path, text_rules)
                except Exception as e:
                    logs.critical(e)
            else:
                try:
                    with open(origin) as f:
                        text_rules = f.read()
                except Exception as e:
                    logs.critical(e)

            raw_rules.extend(text_rules.splitlines())

    filterset = adblock.FilterSet()
    filterset.add_filters(raw_rules)

    return adblock.Engine(filterset)


def label_resources(resources: List[resource], adblocker: adblock.Engine) -> None:
    """Set tracker attribute for resources according to adblock"""
    for resource in resources:
        hostname = urlparse(resource.url).netloc
        result = adblocker.check_network_urls_with_hostnames(
            resource.url, hostname, resource.first_party, resource.get_type()
        )
        resource.is_tracker = result.matched
        resource.filter = result.filter


def get_attr(packet, attr):
    key = attr.split(".")[0]
    layer = get_layer(packet, key)
    return layer[attr] if layer else None


def collect_data(resources, capture, to_collect, cast={}):
    for k, v in to_collect.items():
        for resource in resources:
            collected = [get_attr(capture[idx - 1], v)
                         for idx in resource.packets]
            if k in cast:
                fn = cast[k]
                collected = [fn(attr) for attr in collected]
            resource.__setattr__(k, collected)


def preprocess_study(study, adblocker):
    capture = study / conf["preprocess"].get("capture", "capture.json")
    if not capture.is_file() or conf["preprocess"].getboolean("override", False):
        pcap_to_json(study)

    first_party = study.parent.parent.name
    data = load_json(capture)
    if data is None:
        logs.error(f"No capture found at {capture}")
        return []

    resources = create_resources(data, first_party, study.name)
    label_resources(resources, adblocker)

    collect = eval(conf["preprocess"].get("collect", "{}"))
    cast = eval(conf["preprocess"].get("cast", "{}"))
    collect_data(resources, data, collect, cast)

    if conf["preprocess"].getboolean("keep_capture", False):
        set_tracker(data, resources)
        write_json(data, capture)
        logs.info(f"Keep capture at {capture}")
    else:
        capture.unlink()

    return resources


def run(cur_dir):
    logs.debug(f"Preprocess {cur_dir}")
    adblocker = load_adblock()
    study_folders = [x for x in cur_dir.iterdir() if x.is_dir()]
    resources = []
    for study in study_folders:
        resources.extend(preprocess_study(study, adblocker))

    resources = [resource.__dict__ for resource in resources]

    if conf["preprocess"].getboolean("keep_resource", True):
        resources_path = cur_dir / \
            conf["preprocess"].get("resources", "resources.json")
        logs.debug(f"resources at {resources_path}")
        write_json(resources, resources_path)
    logs.info(f"Finished {cur_dir}")
    return resources


def final(resources, out_path):
    logs.debug("Generate resources")
    resources = pd.DataFrame(resources)

    resources["start_time"] = resources["rel_time"].apply(lambda x: x[0])
    resources["end_time"] = resources["rel_time"].apply(lambda x: x[-1])
    resources["delta_time"] = resources.sort_values("start_time").groupby(
        ["study_name", "website_call", "hostname"], group_keys=False)["start_time"].apply(lambda x: x - x.shift()).fillna(0)

    resources["incoming"] = resources.apply(
        lambda row: [
            row["packets"][i]
            for i, ip in enumerate(row["ip_src"])
            if not ip.startswith("172.17")
        ],
        axis=1,
    )
    resources["incoming_sizes"] = resources.apply(
        lambda row: [
            row["sizes"][i]
            for i, ip in enumerate(row["ip_src"])
            if not ip.startswith("172.17")
        ],
        axis=1,
    )

    resources["outgoing"] = resources.apply(
        lambda row: [
            row["packets"][i]
            for i, ip in enumerate(row["ip_src"])
            if ip.startswith("172.17")
        ],
        axis=1,
    )
    resources["outgoing_sizes"] = resources.apply(
        lambda row: [
            row["sizes"][i]
            for i, ip in enumerate(row["ip_src"])
            if ip.startswith("172.17")
        ],
        axis=1,
    )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    resources.to_csv(out_path, index=False)
    logs.info(f"Saved resources at {out_path}")


def main():
    if not check_requirements():
        exit()

    logs.info(f"Configuration used {config.todict(conf)}")
    raw = Path(conf["output"]["data_path"]) / "raw"
    logs.info(f"Reading from {raw}")
    folders = [
        Path(cur_dir)
        for parent_dir in list_dir(raw)
        for cur_dir in list_dir(parent_dir)
    ]

    resources = []
    with ProcessPoolExecutor() as executor:
        for resource in tqdm(executor.map(run, folders), total=len(folders)):
            resources.extend(resource)

    resources_path = (
        Path(conf["output"]["data_path"])
        / "preprocessed"
        / conf["preprocess"].get("resources", "resources.csv")
    )
    resources_path = resources_path.with_suffix(".csv")
    final(resources, resources_path)


if __name__ == "__main__":
    main()
