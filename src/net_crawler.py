import time
import os
import docker
import config
import requests
from pathlib import Path
from docker.models.containers import Container
from itertools import repeat
from tqdm import tqdm
from concurrent.futures import ProcessPoolExecutor, TimeoutError
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.common.exceptions import NoSuchFrameException, StaleElementReferenceException, TimeoutException
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.remote.webelement import WebElement
from utils.utility import sha3, create_folder, rm_folder, write_file, append_file, init_logger, load_linesperated_textfile, str_sim
from datetime import datetime
from urllib.parse import urlparse
from typing import Dict, Tuple

conf = config.load_config()
logs = init_logger("Crawler", conf, verbose=True)


class CrawlManager:

    def __init__(self, crawl_config: Dict, cookie_accept: Dict) -> None:
        self.crawl_config = crawl_config
        self.cookie_accept = cookie_accept

        self.website = crawl_config['website']
        self.timeout = conf["crawler"].getfloat("timeout", 10)
        self.wait_page = conf["crawler"].getfloat("wait_page", 10)

        self.docker_client = docker.from_env()
        self.crawler, self.port = self._start_crawler()
        self.tcpdump = None
        self.driver = None

    def _get_webdriver(self):
        USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.79 Safari/537.36"

        options = webdriver.ChromeOptions()
        options.add_argument(f"user-agent={USER_AGENT}")
        options.add_argument("--window-size=1920,1080")
        options.add_argument("--lang=de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7")
        options.add_argument("--user-data-dir=chrome-data")
        options.add_argument("--disable-cookie-encryption")

        # bot detection
        options.add_argument('--disable-blink-features=AutomationControlled')

        # Options to avoid errors (disabling features)
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-browser-side-navigation")
        options.add_argument("--disable-gpu")
        options.add_argument("--disable-features=VizDisplayCompositor")
        options.add_argument("--headless")
        options.add_argument("--no-sandbox")
        options.add_argument("--dns-prefetch-disable")

        driver = webdriver.Remote(
            f"http://127.0.0.1:{self.port}", options=options)
        driver.execute_script(
            "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")

        driver.set_page_load_timeout(self.timeout)
        return driver

    def checkready(self):
        iteration = 0
        while True:
            if iteration >= self.timeout:
                raise TimeoutError(
                    f"Timeout ({self.timeout}), couldn't start crawler for {self.website}")
            time.sleep(1)
            try:
                logs.debug(
                    f"Try starting crawler in iteration {iteration} for {self.website}")
                r = requests.get(f"http://localhost:{self.port}/wd/hub/status")
                if r.json()['value']['ready']:
                    break
            except:
                pass
            iteration += 1

    def _start_crawler(self) -> Tuple[Container, int]:
        image = conf["docker"].get("crawler_image", "chrome-crawler")
        ssl = conf["crawler"].get("ssl", "sslkeylogfile.txt")
        volume = self.crawl_config["volume"]

        crawler = self.docker_client.containers.run(image, detach=True, auto_remove=True, ports={
            "4444/tcp": None}, environment=[f"SSLKEYLOGFILE=ssl/{ssl}"], volumes=[f"{volume}/:/ssl/"])

        for offloading in ["tso", "gso", "gro", "lro", "rx", "tx"]:
            crawler.exec_run(
                f"ethtool -K eth0 {offloading} off", privileged=True)

        crawler.reload()
        port = crawler.ports['4444/tcp'][0]['HostPort']

        return crawler, port

    def _start_tcpdump(self, attach: Container = None, volume: str = None) -> Container:
        capture_filter = "tcp port 80 or tcp port 443 or udp port 53"
        image = conf["docker"].get("tcpdump_image", "kaazing/tcpdump")
        pcap = conf["crawler"].get("pcap", "tcpdump.pcap")
        if not volume:
            volume = self.crawl_config["volume"]

        if attach:
            container_id = attach.id
        else:
            container_id = self.crawler.id

        return self.docker_client.containers.run(image, f'"{capture_filter}" -v -i any -w  tcpdump/{pcap}', detach=True, volumes=[f"{volume}/:/tcpdump/"], network_mode=f"container:{container_id}")

    def _stop_tcpdump(self):
        if self.tcpdump:
            self.tcpdump.reload()
            if self.tcpdump.status == 'running':
                self.tcpdump.stop()
                self.tcpdump.remove()
                self.tcpdump = None

    def _rm_cache(self):
        self.crawler.exec_run("rm -rf /chrome-data/Default/Cache/Cache_Data")
        self.crawler.exec_run(
            "rm -rf /chrome-data/Default/Code\ Cache")
        self.crawler.exec_run("rm -rf /chrome-data/Default/GPUCache")

    def close(self):
        self.crawler.stop()
        self._stop_tcpdump()

    def _visit_page(self):
        logs.debug(f"Visit {self.website}")
        self.driver.get(self.website)
        if conf["crawler"].getboolean("scroll", True):
            self._scroll()

    def _scroll(self):
        actions = ActionChains(self.driver)
        for _ in range(2):
            actions.send_keys(Keys.SPACE).perform()
            time.sleep(.4)
        self.driver.execute_script(
            "window.scrollTo(0, document.body.scrollHeight);")
        time.sleep(.4)
        self.driver.execute_script("window.scrollTo(0, 0);")

    def _init_study(self, name):
        self.driver = self._get_webdriver()

        volume = self.crawl_config["volume"]
        if name:
            volume = volume / name
            create_folder(volume)
        self.tcpdump = self._start_tcpdump(volume=volume)

        for i in range(int(self.timeout)):
            self.tcpdump.reload()
            if self.tcpdump.status == 'running':
                break

            time.sleep(1)
            if i == self.timeout:
                raise TimeoutError(
                    f"Timeout ({self.timeout}), couldn't start tcpdump for {self.website}")

        logs.debug(
            f"Successfully initialized study={name} for {self.website}")
        return volume

    def _stop_study(self):
        self._stop_tcpdump()
        if self.driver:
            self.driver.quit()
        self._rm_cache()

    def run_study(self, name=None):
        logs.info(f"Run study {name} for {self.website}")
        volume = self._init_study(name)

        timeout = time.time() + self.wait_page
        try:
            self._visit_page()
            wait = max(0, timeout - time.time())
            time.sleep(wait)
        except TimeoutException as e:
            logs.critical(f"Timeout while {name} {self.website} - {e}")
        except Exception as e:
            logs.error(f"Error while {name} {self.website} - {e}")
            self._stop_study()
            logs.info(f"End study {name} for {self.website}")
            return

        if conf["crawler"].getboolean("screenshots", False):
            screenshot = str(volume / "screenshot.png")
            self.driver.save_screenshot(screenshot)
        self._stop_study()
        if conf["crawler"].getboolean("cookie", False):
            os.system(
                f"docker cp {self.crawler.id}:/chrome-data/Default/Cookies {(volume / 'Cookies.sqlite').resolve()}")
            os.system(
                f"docker cp {self.crawler.id}:/chrome-data/Default/Local\ Storage {str(volume)}")

        logs.info(f"End study {name} for {self.website}")

    def accept_cookie(self, name=None):
        logs.info(f"Run study {name} for {self.website}")
        self._init_study(name)

        timeout = time.time() + self.timeout
        try:
            clicked_banner = self._accept_cookie(timeout=timeout)
        except (TimeoutException, TimeoutError):
            logs.critical(
                f"Timeout ({self.timeout} s) for cookie-accept on {self.website}")
            clicked_banner = False

        except Exception as error:
            logs.error(
                f"Error while accept cookie on {self.website} - {error}")
            clicked_banner = False

        if clicked_banner:
            append_file(self.cookie_accept["log"],
                        f'{self.website},True,"{clicked_banner}"')
            # Time to settle for cookies
            wait = max(0, min(self.wait_page, timeout - time.time()))
            time.sleep(wait)

        else:
            logs.debug(f"No matching cookie-banner at {self.website}")
            append_file(self.cookie_accept["log"], f"{self.website},False,")

        self._stop_study()
        logs.info(f"End study {name} for {self.website}")
        return clicked_banner

    def _accept_cookie(self, timeout):
        self._visit_page()

        clicked_banner = self._click_banner(timeout)
        if not clicked_banner:
            clicked_banner = self._click_frame(timeout)

        return clicked_banner

    def _is_Accept_Word(self, banner_text, accept_words):
        if not banner_text:
            return False
        if conf["crawler"].getboolean("check_accept_words_sim", False):
            if banner_text in accept_words:
                return True
            if any(str_sim(banner_text, accept) > 0.9 for accept in accept_words):
                logs.debug(f"Similar cookie text for {banner_text}")
                return True
        else:
            return banner_text in accept_words

    def _find_banner(self, timeout):
        contents = [elem for tag in ["button", "a"]
                    for elem in self.driver.find_elements(By.TAG_NAME, tag)]
        accept_words = self.cookie_accept['words']

        for candidate in contents:
            if time.time() > timeout:
                raise TimeoutError
            try:
                banner_text = candidate.text.lower().strip(" ✓›!\n")
                banner_text = ' '.join(banner_text.splitlines())
                if self._is_Accept_Word(banner_text, accept_words):
                    id = candidate.get_attribute("id")
                    logs.debug(
                        f"Found id: {id}, tag_name: {candidate.tag_name}, text: {candidate.text}")
                    return candidate

            except:
                logs.error("Exception in processing element: {} at {}".format(
                    candidate.id, self.driver.current_url))

        return None

    def _click_banner(self, timeout):
        candidate = self._find_banner(timeout)
        # Click the candidate
        if candidate:
            original_text = candidate.text
            banner_text = ' '.join(
                candidate.text.lower().strip(" ✓›!\n").splitlines())
            try:  # in some pages element is not clickable
                candidate.click()
                logs.debug(
                    "Clicked cookie-banner at {} with text {}".format(self.driver.current_url, original_text))
                return banner_text
            except Exception:
                try:
                    self.driver.execute_script(
                        f"arguments[0].click();", candidate)
                    logs.debug(
                        "Clicked cookie-banner at {} with text {}".format(self.driver.current_url, original_text))
                    return banner_text
                except Exception as e:
                    logs.error(
                        f"Exception in cookie-banner click at {self.driver.current_url}\n{e}")
        return False

    def _click_frame(self, timeout):
        frames = self.driver.find_elements(By.TAG_NAME, "iframe")

        for frame in frames:
            if time.time() > timeout:
                raise TimeoutError

            if not isinstance(frame, WebElement):
                continue
            try:
                logs.debug("Switching to frame: {} ({})".format(
                    frame.id, frame.get_attribute("title")))
                self.driver.switch_to.frame(frame)
                clicked_banner = self._click_banner(timeout)
                self.driver.switch_to.default_content()
                if clicked_banner:
                    return clicked_banner
            except NoSuchFrameException:
                self.driver.switch_to.default_content()
                logs.error(
                    f"Error in switching to frame at {self.driver.current_url}")
            except StaleElementReferenceException:
                logs.error(
                    f"Element not found in DOM at {self.driver.current_url}")

        return False


def setup_docker():
    client = docker.from_env()
    crawler_image = conf["docker"].get("crawler_image", "chrome-crawler")
    try:
        client.images.get(crawler_image)
    except docker.errors.ImageNotFound:
        p = config.PROJECT / "docker" / f"Dockerfile-{crawler_image}"
        with open(p, "rb") as f:
            client.images.build(fileobj=f, tag=crawler_image)

    return client


def create_study_config(limit_study=None):
    raw_path = Path(conf["output"].get("data_path", "data")) / "raw"
    websites = conf["crawler"].get("web_pages", None)
    if not websites:
        logs.critical("Specify option 'web_pages'")
        return None

    websites = load_linesperated_textfile(websites)

    def has_protocol(x):
        return x.startswith("http://") or x.startswith("https://")
    websites = [
        "https://" + website if not has_protocol(website) else website for website in websites]
    if limit_study:
        websites = websites[:limit_study]

    study_config = {"raw": raw_path, "websites": websites}

    accept_words = conf["crawler"].get("accept_words", None)
    if accept_words:
        accept_words = set(load_linesperated_textfile(accept_words))
        accept_log = (Path(conf["output"].get("data_path", "data"))
                      / "preprocessed"
                      / f"Cookie-Accept-{datetime.today().strftime('%Y-%m-%d')}.csv")
        study_config['cookie_accept'] = {
            "words": accept_words, 'log': accept_log}
    else:
        study_config['cookie_accept'] = None

    return study_config


def create_crawl_config(study_config):
    crawl_config = []
    for website in study_config["websites"]:
        vol_path = (study_config["raw"]
                    / urlparse(website).netloc
                    / sha3(website)[:10])
        if not vol_path.exists():
            logs.debug(f"Output path {vol_path} created")
            create_folder(vol_path)
        elif conf["crawler"].getboolean("override", False):
            # Study already exists and should be overridden
            logs.info(
                f"Study at {vol_path} already exists and will be overridden")
            rm_folder(vol_path)
            create_folder(vol_path)
        else:
            # Study already exists and should not be overridden
            logs.info(f"Study at {vol_path} already exists and will be skiped")
            continue

        crawl_config.append({"website": website, "volume": vol_path.resolve()})

    return crawl_config


def setup_config():
    logs.info(f"Configuration used {config.todict(conf)}")
    limit_study = conf["crawler"].getint("limit_study", 0)

    study_config = create_study_config(limit_study=limit_study)
    if not study_config:
        return None

    logs.info(
        f"Start study at {config.PROJECT} with input {conf['crawler']['web_pages']} and output {study_config['raw']}")
    crawl_config = create_crawl_config(study_config)

    if conf["crawler"].getboolean("origin_req", True):
        for crawl in crawl_config:
            write_file(crawl["volume"] / "request.txt", crawl["website"])

    if study_config["cookie_accept"]:
        write_file(study_config["cookie_accept"]
                   ["log"], "url,is_accept,banner_text")

    return study_config, crawl_config


def run_crawl(crawl_config, cookie_accept):
    crawl = CrawlManager(crawl_config, cookie_accept)
    try:
        crawl.checkready()
        crawl.run_study("before accept")
        clicked_banner = crawl.accept_cookie("accepting policy")
        if clicked_banner:
            crawl.run_study("after accept")
    except Exception as e:
        logs.error(f"Error for {crawl_config['website']} - {e}")
    finally:
        crawl.close()


def main():
    study_config, crawl_config = setup_config()
    start = datetime.now()
    setup_docker()

    n_container = int(conf["docker"].get("n_container", "5"))
    with ProcessPoolExecutor(max_workers=n_container) as executor:
        list(tqdm(executor.map(run_crawl, crawl_config, repeat(
            study_config["cookie_accept"])), total=len(crawl_config)))

    logs.info(f"Done ({(datetime.now() - start).total_seconds():.1f} seconds)")
    print(f"See results at '{study_config['raw'].resolve()}'")


if __name__ == "__main__":
    main()
