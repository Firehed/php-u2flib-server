<?php
require_once '../common.php';
$name = $_POST['username'];
$uf = new UserFinder($pdo);
$user = $uf->find($name);
if (!$user) { throw new Exception('User not found'); }

$regs = $user->getRegistrations();
$req_data = $u2f->getAuthenticateData($regs);
echo json_encode($req_data);
