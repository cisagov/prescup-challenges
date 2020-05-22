<img src="../../logo.png" height="250px">

# Python Security Pick 'Em (Individual)
#### Category: Securely Provision
#### Difficulty Level: 500
#### Executive Order Category: Secure Programming

## Background
In this challenge, you will be asked to assess four different functions written in Python. Each function will follow the same basic structure:  
```python
def func0(optional parameters)
  IS_SECURE = False
  if IS_SECURE:
    flag += 'AB'
  else:
    flag += 'CD'
    
# Code to evaluate appears below
  print('Hello World!')
  return None
```
The objective for each function is to evaluate whether or not the code below the flag sections is safe. Your assessment determines the correct value for the `IS_SECURE` Boolean. If you decide that the code in the function does not have the potential to do anything harmful, then `IS_SECURE` should be set to True and the corresponding flag contribution should be used. By default, `IS_SECURE` is set to `False` for every function. This does not mean `False` is the correct value.    
  
The four functions will be numbered 0 through 3 and each will contribute two characters to your flag file. You can assume the functions would run in order, so the flag file would be constructed as follows:
```
00112233
```
\## is the two character flag contribution of function number X. Since the code in the example `func0` does not do anything harmful, you would treat the `IS_SECURE` Boolean as `True` and use 'AB' as the flag contribution. Therefore this example flag would look like
```
AB112233
```
with three evaluations remaining.

## Additional Information

During the President's Cup, the challenge deployment server would run required/generate.py to pick two from each pool of
safe/unsafe functions. All eight have been provided in this public repository both in the challenge directory with
generic names, as well as the solution directory separated into their pools and named with the correct flag segment.

The flaganalysis.py file in the solution directory can also automatically evaluate whether a four-segment flag is
correct or not, and also contains the reasoning for their category.

## Clarification

It was not specified in the original lab guide, but this challenge was written with Python 3 syntax and code in mind.
However, none of the functions in this challenge would have a different answer in Python 2 (other than that some would
be syntactically incorrect, which was not being tested).

## License
Copyright 2020 Carnegie Mellon University. See the [LICENSE.md](../../LICENSE.md) file for details.