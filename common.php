<?php
ini_set('display_errors', true);
require_once 'u2f.php';

$pdo = new PDO("sqlite:/home/sites/u2f.ericstern.com/reg.sqlite");
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_OBJ);
// basic table schema
$pdo->exec("create table if not exists users (id integer primary key, name varchar(255))");
$pdo->exec("create table if not exists registrations (id integer primary key, user_id integer, keyHandle varchar(255), publicKey varchar(255), certificate text, counter integer)");

use u2flib_server\RegistrationInterface;

class User {
    private $db;

    public $id;
    public $name;

    public function __construct(PDO $db) {
        $this->db = $db;
    }
    public function getRegistrations() {
        $select = $this->db->prepare("SELECT * FROM registrations WHERE user_id = ?");
        $select->execute([$this->id]);
        $regs = $select->fetchAll();
        $out = [];
        foreach ($regs as $reg) {
            $out[] = (new UserRegistration())->setPDO($this->db)->_load($reg);
        }
        return $out;
    }
    private function addRegistration(RegistrationInterface $reg) {
        $ins = $this->db->prepare("INSERT INTO registrations (user_id, keyHandle, publicKey, certificate, counter) VALUES (?, ?, ?, ?, ?)");
        $ins->execute([
            $this->id,
            $reg->getKeyHandle(),
            $reg->getPublicKey(),
            $reg->getCertificate(),
            $reg->getCounter()
        ]);
        return true;
    }

    // throws if there is a bad signature
    public function registerSignature($u2f, $request, $signature) {
        $reg = $u2f->doRegister($request, $signature);
        $this->addRegistration($reg);
    }


    public function authenticateSignature($u2f, $request, $signature) {
        $auth = $u2f->doAuthenticate($request, $this->getRegistrations(), $signature);
    }

}

class UserRegistration
    extends u2flib_server\Registration
//    implements JsonSerializable
{

    private $db;

    private $id;
    private $user_id;

    public function setPDO(PDO $db) {
        $this->db = $db;
        return $this;
    }
    public function _load($data) {
        $this->id = $data->id;
        $this->user_id = $data->user_id;
        return $this
            ->setKeyHandle($data->keyHandle)
            ->setPublicKey($data->publicKey)
            ->setCertificate($data->certificate)
            ->setCounter($data->counter);
    }

    // intercept to persist
    public function validateCounter($hardware_value) {
        parent::validateCounter($hardware_value);
        $this->saveCounter();
    }
/*
    public function jsonSerialize() {
        return [
            'id' => $this->id,
            'user_id' => $this->user_id,
            'keyHandle' => $this->keyHandle,
            'publicKey' => $this->publicKey,
            'certificate' => $this->certificate,
            'counter' => $this->counter,
        ];
    }
*/
    // this is not optimal, the stock u2f lib updates the value in place rather than using proper accessors
    private function saveCounter() {
        $up = $this->db->prepare('UPDATE registrations SET counter=? where id=?');
        $up->execute([$this->getCounter(), $this->id]);
        return true;
    } 
}

class UserFinder {
    public function __construct(PDO $db) {
        $this->db = $db;
    }
    public function find($name) {
        $sel = $this->db->prepare('SELECT * FROM users WHERE name = ?');
        $sel->execute([$name]);
        $data = $sel->fetch();
        if (!$data) {
            return null;
        }
        $user = new User($this->db);
        $user->id = $data->id;
        $user->name = $data->name;
        return $user;
    }

    public function findOrCreate($name) {
        $user = $this->find($name);
        if (!$user) {
            $ins = $this->db->prepare('INSERT INTO users (name) VALUES (?)');
            $ins->execute([$name]);
        }
        return $this->find($name);
    }
}


header('Content-type: application/json');
$u2f = new u2flib_server\U2F('https://'.$_SERVER['HTTP_HOST']);
set_exception_handler(function($e) {
    header('HTTP/1.1 400 Bad Request');
    echo json_encode(['error' => $e->getMessage()]);
});
set_error_handler(function($a,$b,$c,$d) { throw new \ErrorException($b,0,$a,$c,$d); }, -1);


