# Integrate With Vulnerability Server

There are some controls that check the relation between the kubernetes manifest and vulnerabilities.
For these controls to work properly, it is necasery to 
## Supported Servers
* Armosec

# Integrate With Armosec Server

1. Navigate to the [armosec.io](https://portal.armo.cloud/)
2. Click Profile(top right icon)->"User Management"->"API Tokens" and Generate a token
3. Copy the clientID and accessKey and run:
```
kubescape set config --access-key <> --client-id <>
```
4. Confirm the keys are set
```
kubescape view config
```
Expecting:
```
{
  "accountID": "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
  "clientID": "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
  "accessKey": "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
}
```
> If you are missing the `accountID` field, set it by running `kubescape set config --account <>`

For CICD, set environments variables as following:
```
KS_ACCOUNT_ID  // account id
KS_CLIENT_ID   // client id
KS_ACCESS_KEY  // access key
```