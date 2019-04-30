# MasherySigner
Burp Extension for Mashery Signing 

Add your API Key and API Secret to the properties in the extension tab. At this 
time, only SHA256 signatures are supported. 

The extension will look for both the `api_key` and `sig` query parameters in all
requests being sent by Burp. If it finds a request, it will update the signature
in the query. 

## Example Request

The extension takes an existing Mashery request and updates the `api_key` and 
`sig` parameters.

Here's an example of a Mashery request that the extension will update:

```
GET /mashery/api/endpoint?api_key=abcdefhijklmnopqrstuvwx&sig=7abdf02dd9224a2367fd78fa12596c49d0a154c4ab73abe3e6dc822ef565a0c6 HTTP/1.1
User-Agent: MyApp/1.23.4/Android/8.0.0
Host: api.example.com
Connection: close
Accept-Encoding: gzip, deflate
```

More information about Mashery's request signing can be found here: 
* https://support.mashery.com/docs/read/mashery_api/20/Authentication
* https://docs.mashery.com/design/GUID-517A43A4-F054-41D1-9F5C-C736B557AF88.html

## Download

The most recent jar file can be found in the releases https://github.com/NetSPI/MasherySigner/releases

## Build

1. git clone https://github.com/NetSPI/MasherySigner.git
2. Install gradle for your distribution (https://gradle.org/install/)
3. `cd MasherySigner`
4. `gradle build`
5. JAR file will be in the build/libs directory

## Acknowledgements
MasherySigner is based off of [AWSSigner](https://github.com/netspi/awssigner) 
by Eric Gruber (@egru).