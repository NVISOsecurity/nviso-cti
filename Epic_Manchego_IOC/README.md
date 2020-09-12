# Epic Manchego – atypical maldoc delivery brings flurry of infostealers
In July 2020, NVISO detected a set of malicious Excel documents, also known as “maldocs”, that deliver malware through VBA-activated spreadsheets. While the malicious VBA code and the dropped payloads were something we had seen before, it was the specific way in which the Excel documents themselves were created that caught our attention.

The creators of the malicious Excel documents used a technique that allows them to create macro-laden Excel workbooks, without actually using Microsoft Office. As a side effect of this particular way of working, the detection rate for these documents is typically lower than for standard maldocs.

[This blog post](https://blog.nviso.eu/2020/09/01/epic-manchego-atypical-maldoc-delivery-brings-flurry-of-infostealers/) provides an overview of how these malicious documents came to be. In addition, it briefly describes the observed payloads and finally closes with recommendations as well as indicators of compromise to help defend your organization from such attacks.

The IoCs and Yara rules related to operation Epic Manchego are released through this repository.
