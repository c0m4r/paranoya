<?php

$host = "127.0.0.1";
$port = 1337;

$path = $argv[1];

if(isset($argv[2])) {
    $auth = $argv[2];
    $message = $path . " " . $auth;
} else {
    $message = $path;
}

if(!is_file($path) and !is_dir($path))
{
    die("path: $message doesn't exist\n");
}

$socket = @socket_create(AF_INET, SOCK_STREAM, 0);
$result = @socket_connect($socket, $host, $port);

if($result) {
    socket_write($socket, $message, strlen($message)) or die("Could not send data to server\n");
    $result = socket_read ($socket, 2048) or die("Could not read server response\n");
    echo $result;
} else {
    echo 'not connected';
}

echo "\n";

socket_close($socket);

?>
