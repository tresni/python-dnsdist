# python-dnsdist
Python library to talk to [dnsdist](http://dnsdist.org)

Since version 1.2.0, dnsdist uses merged nonces to send and receive messages, while pre 1.2.0 dnsdist does not.

By default, this library will use merged nonces. To disable, set the merge\_nonces argument to False.

## Requirements

* [libnacl](https://libnacl.readthedocs.org/) is required if you need to talk to a dnsdist instance that is compiled with libsodium support

  ```
  pip install libnacl
  ```

## Example
```python
from DNSDist import Console

# Connect to dnsdist on localhost:5199 without a key
console = Console()
print console.execute('showServers()')
```

```python
from DNSDist import Console

# Connect to dnsdist 1.2.0+ instance on 10.100.1.2:3200 with supplied key
console = Console(key='tZ+bElqKb+moWK1BAAlSjIjAdVb9zTXT7Ziqj/lw/R8=', host='10.100.1.2', port=3200)
print console.execute('showServers()')
```

```python
from DNSDist import Console

# Connect to dnsdist pre 1.2.0 instance on 10.100.1.2:3200 with supplied key
console = Console(key='tZ+bElqKb+moWK1BAAlSjIjAdVb9zTXT7Ziqj/lw/R8=', host='10.100.1.2', port=3200, merge_nonces=False)
print console.execute('showServers()')
```

```python
from DNSDist import Console

# Connect to dnsdist instance on 10.100.1.2 and do not use libsodium even if its available
console = Console(host='10.100.1.2', have_sodium=False)
print console.execute('showServers()')
```
