<?php
require_once '../common.php';
$name = $_POST['username'];
$uf = new UserFinder($pdo);
$user = $uf->findOrCreate($name);
$regs = $user->getRegistrations();

$req_data = $u2f->getRegisterData($regs);
list($request, $sigs) = $req_data;

$out = [
    'request' => $request,
    'signatures' => $sigs,
];
echo json_encode($out);
