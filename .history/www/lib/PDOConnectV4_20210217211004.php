<?php
class PDOConnectV4{
	var $host;
	var $username;
	var $password;
	var $db;
	var $conn;
	var $ret=array('c'=>0,'e'=>'','v'=>array());
	var $rsc;
	var $setName='utf8';


	function __construct($dbName){
		if($dbName =="sm" ){		
			$this->host='db';
			$this->username='user';			
			$this->password='dGVzdA==';
			// $this->db='rs_mergev3';
			$this->db='smilemigraine';
		}
		
	}
	
	public function Open(){

		$this->conn = new PDO("mysql:host=$this->host;dbname=$this->db", $this->username, base64_decode($this->password));
	    $this->conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

		if($this->setName!=''){
			$this->conn->query("set names '".$this->setName."'");
		}

		return $this->conn;
	}	
	public function Close(){
		$this->conn=null;
	}
	public function Open2(){
		$this->conn=new mysqli($this->host,$this->username,base64_decode($this->password),$this->db)or die("can not connect database server  $this->host ");
		if($this->setName!=''){
			// $this->conn->query("set names '$setName'");
			$this->conn->query($this->setName);

		}
		return $this->conn;
	}
}
?>