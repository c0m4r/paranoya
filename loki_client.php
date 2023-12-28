<?php

$host = "127.0.0.1";
$port = 1337;

$message = $argv[1];

if(!is_file($message) and !is_dir($message))
{
    die("path: $message doesn't exist\n");
}

$socket = @socket_create(AF_INET, SOCK_STREAM, 0);
$result = @socket_connect($socket, $host, $port);

if($result) {
    socket_write($socket, $message, strlen($message)) or die("Could not send data to server\n");
    $result = socket_read ($socket, 1024) or die("Could not read server response\n");
    echo $result;
} else {
    echo 'not connected';
}

echo "\n";

socket_close($socket);

?>
