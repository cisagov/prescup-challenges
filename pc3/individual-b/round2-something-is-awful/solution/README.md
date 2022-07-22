# Something is Awful Solution

## SQL Injection Check  

- Edit awfulbb/app.py and make the following change:
    - Line 49:
        ```python
        cursor.execute( "SELECT id, username, password FROM user WHERE username = %(username)s and password = %(password)s", {'username':request.form['username'],'password':request.form['password'] }  )
        ```
## Blind SQL Injection
- Edit awfulbb/app.py with vim and make the following change:
    - Line 65:
  
        ```python
        cursor.execute( "SELECT id, title, author, posted as date FROM thread WHERE id = %(threadId)s", { 'threadId': threadId } )
         ```

## XSS Vuln
- Edit awfulbb/templates/thread.html:
    - Remove the following from Line 8:

        ```html
        | safe
        ```
        
## Restart
---
Ctrl-C in the terminal window running wsgi.py to stop the web server. Start it again by running: 
```python
python3 ./wsgi.py
```

## Check
---
In a terminal run 
    
```bash
sudo python3 grade-challenge.py
```