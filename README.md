# SSH Filter

## Usage

In root privilege, write the following command to filter the IP address.

- add the IP address to the blacklist(b)/whitelist(w)
- IP will be deleted from the blacklist/whitelist when it is added to the whitelist/blacklist.

```shell
echo "b [ip]" > /dev/ssh_filter
echo "w [ip]" > /dev/ssh_filter
```

- switch the mode of the filter
- [mode]: "b" for blacklist mode, "w" for whitelist mode
```shell
echo "m [mode]" > /dev/ssh_filter
```

- show the blacklist and whitelist
```shell
cat /dev/ssh_filter
```