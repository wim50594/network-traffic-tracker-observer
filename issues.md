This document describes current issues in this project.

## Crawler
1) Puppeteer: Currently Selenium is used. Puppeteer is a promising API to automate chrome headless. Selenium makes often trouble, e.g. unexpected crashes or not finding meta tags in the html document. Also with Selenium it is not possible to get third party cookies embedded on the first party website.
2) <s>TCP Segmentation Offloading: Sender byte size sometimes exceeds MTU limit (1500 bytes). This is because of TCP segmentation offloading (tso) which means network traffic is segmented by NIC. Further reading:</s>
    - https://wiki.wireshark.org/CaptureSetup/Offloading
    - https://blog.securityonion.net/2011/10/when-is-full-packet-capture-not-full.html  
**Possible solution**  
`ethtool -K IFACE_NAME tso off`  
`ethtool --offload IFACE_NAME rx off tx off`  