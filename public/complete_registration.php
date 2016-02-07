<?php
require_once '../common.php';
// the user needs to come from the active session, not a form, or anyone could attach their key to any other user
$name = $_POST['username'];
$uf = new UserFinder($pdo);
$user = $uf->find($name);
if (!$user) { throw new Exception('User not found'); }

$request = json_decode($_POST['request_str']);
$signature = json_decode($_POST['signature_str']);
$user->registerSignature($u2f, $request, $signature);
echo json_encode('Registration successful!');
