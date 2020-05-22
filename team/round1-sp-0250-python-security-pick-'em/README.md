<img src="../../logo.png" height="250px">

# Python Security Pick 'Em
#### Category: Securely Provision
#### Difficulty Level: 250
#### Executive Order Category: Secure Programming

## Background  
In this challenge, you will be asked to assess ten different functions written in Python 2.7. Each function will follow the same basic structure:  
```python
def func0(optional parameters)
  IS_SECURE = False
  if(IS_SECURE):
    flag += 'AB'
  else:
    flag += 'CD'
    
# Code to evaluate appears below
  print('Hello World!')
  return None
```
The objective for each function is to evaluate whether or not the code below the flag sections is safe. Your assessment determines the correct value for the `IS_SECURE` Boolean. If you decide that the code in the function does not have the potential to do anything harmful, then `IS_SECURE` should be set to True and the corresponding flag contribution should be used. By default, `IS_SECURE` is set to `False` for every function. This does not mean `False` is the correct value.    
  
The ten functions will be numbered 0 through 9 and each will contribute two characters to your flag file. You can assume the functions would run in order, so the flag file would be constructed as follows:
```
00112233445566778899
```
\## is the two character flag contribution of function number X. Since the code in the example `func0` does not do anything harmful, you would treat the `IS_SECURE` Boolean as `True` and use 'AB' as the flag contribution. Therefore this example flag would look like
```
AB112233445566778899
```
with nine evaluations remaining.

## License
Copyright 2020 Carnegie Mellon University. See the [LICENSE.md](../../LICENSE.md) file for details.