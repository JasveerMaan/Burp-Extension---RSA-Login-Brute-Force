# Burp-Extension-RSA-Login-Brute-Force

One of my assessment scope is to test login page of a web application. I noticed that the web applciation encrypts my login credentials which makes it harder to check for certain test cases. I wrote this extension to capture the server response to retrive "Public Key" and "Random Number" and then use JavaScript (from the server) to encrypt my plaintext password. Parameter "c_string" is where I insert my plaintext password and then Burp extension will handle the rest (to encrypt). This allows me to use Burp Suite Intruder feature. Please take note to set "Threads" to 1 for brute forcing.

# To Do
1. Implement multithreading
