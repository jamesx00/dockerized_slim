<?php
// print_r('test 1234');
use \Psr\Http\Message\ServerRequestInterface as Request;
use \Psr\Http\Message\ResponseInterface as Response;
// Sentry\init([
//     'dsn' => 'https://b6b84a57421647a8b4ae66f87336cc47@o467163.ingest.sentry.io/5493102',
//     'traces_sample_rate' => 1.0 # be sure to lower this in production to prevent quota issues
//     ]);
require __DIR__ . '/vendor/autoload.php';
require  __DIR__ . '/services/storage.php';
require  __DIR__ .  '/servicesV4/storage.php';
cors();
function cors() {

    // Allow from any origin
    if (isset($_SERVER['HTTP_ORIGIN'])) {
        // Decide if the origin in $_SERVER['HTTP_ORIGIN'] is one
        // you want to allow, and if so:
        header("Access-Control-Allow-Origin: {$_SERVER['HTTP_ORIGIN']}");
        header('Access-Control-Allow-Credentials: true');
        header('Access-Control-Max-Age: 86400');    // cache for 1 day
    }
    // Access-Control headers are received during OPTIONS requests
    if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
        if (isset($_SERVER['HTTP_ACCESS_CONTROL_REQUEST_METHOD'])){
            // may also be using PUT, PATCH, HEAD etc
            header("Access-Control-Allow-Methods: GET, POST, PUT, PATCH, OPTIONS, DELETE");         
        }
        if (isset($_SERVER['HTTP_ACCESS_CONTROL_REQUEST_HEADERS'])){
            header("Access-Control-Allow-Headers: {$_SERVER['HTTP_ACCESS_CONTROL_REQUEST_HEADERS']}");
        }
        exit;
    }
}
function getAuthorizationHeader(){
    $headers = null;
    if (isset($_SERVER['Authorization'])) {
        $headers = trim($_SERVER["Authorization"]);
    }
    else if (isset($_SERVER['HTTP_AUTHORIZATION'])) { //Nginx or fast CGI
        $headers = trim($_SERVER["HTTP_AUTHORIZATION"]);
    } elseif (function_exists('apache_request_headers')) {
        $requestHeaders = apache_request_headers();
        // Server-side fix for bug in old Android versions (a nice side-effect of this fix means we don't care about capitalization for Authorization)
        $requestHeaders = array_combine(array_map('ucwords', array_keys($requestHeaders)), array_values($requestHeaders));
        //print_r($requestHeaders);
        if (isset($requestHeaders['Authorization'])) {
            $headers = trim($requestHeaders['Authorization']);
        }
    }
    return $headers;
}

$config = [
    'settings' => [
        'determineRouteBeforeAppMiddlewareV4' => true,
        'displayErrorDetails' => true,
        'addContentLengthHeader' => false,

    ] ,
    ];
$c = new \Slim\Container($config);
$app = new \Slim\App($c);
// Sentry\init([    'dsn' => 'https://b6b84a57421647a8b4ae66f87336cc47@o467163.ingest.sentry.io/5493102' ]);


$app->group('/v3',function() use($app){
    $app->get('/testV3',function(Request $request, Response $response, $args){
                print_r('***V3***');
        return ;
    });
    // THIS FOR CALL DATA IN FIREBASE
    $app->post('/notification', function (Request $request, Response $response,$args) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'send_notification';
        $func = new Middleware();
        // $func->data_check = ['member_id'=>4796];
        $func->data_check = ['member_id'=>$p['member_id']];
        $func->response = $response;
        $func->preCall($p);
        $func->callMethod($p);
       
    });  
    $app->patch('/notification', function (Request $request, Response $response,$args) {
        $p = json_decode($request->getBody(), true);
        
        $p['method'] = 'set_notification';
        $func = new Middleware();
        $func->data_check = ['member_id'=>$p['member_id']];
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
       
    });  
    $app->post('/admin/noti/{member_id:[0-9]+}', function (Request $request, Response $response,$args) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'notification_send';
        $func = new Middleware();
        $func->data_check = ['member_id'=>$p['member_id']];
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });  
    $app->post('/comment', function (Request $request, Response $response,$args) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'firestore_comment';
        $func = new Middleware();
        $func->data_check = ['member_id'=>$p['member_id']];
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });  
    $app->get('/list_comment/{post_id}/{member_id:[0-9]+}',function(Request $request, Response $response,$args){
        $post_id = $request->getAttribute('post_id');
        $member_id = $request->getAttribute('member_id');
        $p['member_id'] = $member_id;
        $p['post_id'] = $post_id;
        
        $p['method'] = 'firestore_listcomment'; 
        $func = new Middleware();

        $func->data_check = ['member_id'=>$p['member_id']];
        
        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        return $response->withJSON($func->callMethod($p)['v']);
    });
    $app->get('/list_post/{member_id:[0-9]+}',function(Request $request, Response $response,$args){
        $member_id = $request->getAttribute('member_id');
        $p['method'] = 'firestore_listpost'; 
        $p['member_id'] = $member_id;
        $func = new Middleware();

        $func->data_check = ['member_id'=>$p['member_id']];
        
        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        return $response->withJSON($func->callMethod($p)['v']);
    });

    $app->get('/last_post',function(Request $request, Response $response,$args){
        $member_id = $request->getAttribute('member_id');
        
        $p['method'] = 'firestore_lastpost'; 
        $p['member_id'] = $member_id;
        $func = new Middleware();

        $func->data_check = ['member_id'=>$p['member_id']];
        
        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        return $response->withJSON($func->callMethod($p)['v']);
    });
    $app->get('/chatRooms',function(Request $request, Response $response,$args){
        $p['method'] = 'firestore_chatrooms'; 
        $func = new Middleware();
        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        return $response->withJSON($func->callMethod($p)['v']);
    });
    $app->post('/likepost', function (Request $request, Response $response,$args) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'firestore_likepost';
        $func = new Middleware();
        $func->data_check = ['member_id'=>$p['member_id']];
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });  
    $app->post('/likecomment', function (Request $request, Response $response,$args) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'firestore_likecomment';
        $func = new Middleware();
        $func->data_check = ['member_id'=>$p['member_id']];
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });  
    $app->post('/setnewchatrooms', function (Request $request, Response $response,$args) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'firestore_newchatroom';
        $func = new Middleware();
        $func->data_check = ['member_id'=>$p['member_id']];
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });  

    $app->get('/purchasing/members/{member_id:[0-9]+}', function (Request $request, Response $response, $args) {
        $p['method'] = 'list_purchase_history'; 
        $func = new Middleware();

        $p['member_id'] = $args['member_id'];
        $func->data_check = ['member_id'=>$p['member_id']];
        
        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        return $response->withJSON($func->callMethod($p)['v']);
    });

     $app->get('/getFirestore',function(Request $request, Response $response){
        $p['method']='firestore';
        $func = new Middleware();
        $func->response = $response;
        $func->preCall($p);
        $rs = $func->callMethod($p);
        // return $response->withJSON($rs);
    });
    $app->get('/jwt/{n:[0-9]+}', function (Request $request, Response $response, $args) {
        $n = $request->getAttribute('n') * 1;
        $p['method']='jwt';
        $config = new Config();
        $cf = $config->cf;
        $jwt = $cf['jwt']['smapi'];
        $auth=new Auth($jwt);
        print_r($auth->setAuth(['group'=>$n,'member_id'=>'1']));
    });
    $app->get('/jwt/t/{token}', function (Request $request, Response $response, $args) {
        $token = $request->getAttribute('token');
        $p['method']='jwt';

        $config = new Config();
        $cf = $config->cf;
        $jwt = $cf['jwt']['smapi'];
        /*
        $log = new Log();
        $log_id = $log->saveLog($p);
        */
        $auth=new Auth($jwt);
        $auth_result = $auth->checkAuthManual($token);
        // print_r($auth_result);exit;
        if($auth_result['valid']){
            include "services/".$p['method'].".php";
            $p['token_data'] = $auth_result['token_data'];
            $rs = $response->withJSON(call_user_func($p['method'], $p));

            if($log_id>0){
                $log->updateLog($log_id,$rs);
            }
            return $rs;
        }
    });
    $app->post('/authentications', function (Request $request, Response $response, $args) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'authentications';
        $func = new Middleware();
        
        $func->response = $response;
        $func->preCall($p);
        $rs = $func->callMethod($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    }); 
    $app->post('/config', function (Request $request, Response $response) {
        $p = json_decode($request->getBody(), true);

        $p['method'] = 'set_config';
        $func = new Middleware();

        $func->data_check = ['member_id'=>$p['member_id']];

        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    }); 
    $app->get('/triggers/{member_id:[0-9]+}',function(Request $request, Response $response,$args){
        $p['method'] = 'list_triggers'; 
        $func = new Middleware();
        if(isset($args['member_id'])){
            $p['member_id'] = $args['member_id'];
            $func->data_check = ['member_id'=>$p['member_id']];
        }
        // print_r($p);
        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        return $response->withJSON($func->callMethod($p)['v']);
    });
    $app->get('/triggers',function(Request $request, Response $response,$args){
        $p['method'] = 'list_all_triggers'; 
        $func = new Middleware();
        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        return $response->withJSON($func->callMethod($p)['v']);
    });

    $app->post('/register', function (Request $request, Response $response) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'regis_member';
        $func = new Middleware();

        $func->response = $response;
        $func->preCall($p);

        $rs = $func->callMethod($p);
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    }); 
    $app->post('/members', function (Request $request, Response $response) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'add_member';
        $func = new Middleware();

        $func->response = $response;
        $func->preCall($p);

        $rs = $func->callMethod($p);
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    }); 
    $app->post('/login', function (Request $request, Response $response) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'login';
        $func = new Middleware();

        $func->response = $response;
        $func->preCall($p);

        $rs = $func->callMethod($p);
        
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });
    $app->get('/symptoms',function(Request $request, Response $response){
        $p['method'] = 'list_symptoms'; 
        $func = new Middleware();
        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        return $response->withJSON($func->callMethod($p)['v']);
    });
    $app->get('/members[/{member_id}]', function (Request $request, Response $response, $args) {
        $p['method'] = 'list_members'; 
        $func = new Middleware();

        if(isset($args['member_id'])){
            $p['member_id'] = $args['member_id'];
            $func->data_check = ['member_id'=>$p['member_id']];
        }

        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        return $response->withJSON($func->callMethod($p)['v']);
    }); 
    $app->patch('/members/{member_id:[0-9]+}', function (Request $request, Response $response) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'update_member';
        $func = new Middleware();
        
        $p['member_id'] = $request->getAttribute('member_id');
        $func->data_check = ['member_id'=>$p['member_id']];
        
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        $rs = $func->callMethod($p);
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs)
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });

    $app->post('/userMedications', function (Request $request, Response $response) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'add_user_medications';
        $func = new Middleware();

        $func->data_check = ['member_id'=>$p['member_id']];

        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        
        if($rs['c']==0){
            return $response->withJSON($rs);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });
    $app->get('/userMedications/{member_id:[0-9]+}/{user_medication_id:[0-9]+}', function (Request $request, Response $response,$args) {
        $p['method'] = 'list_user_medications'; 
        $func = new Middleware();

        if(isset($args['user_medication_id'])){
            $p['user_medication_id'] = $args['user_medication_id'];
            $p['member_id'] = $args['member_id'];
            $func->data_check = ['member_id'=>$p['member_id']];
        }

        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        return $response->withJSON($func->callMethod($p)['v']);
    });
    $app->patch('/userMedications/{member_id:[0-9]+}/{user_medication_id:[0-9]+}', function (Request $request, Response $response,$args) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'update_medication';
        $func = new Middleware();
        
        $p['member_id'] = $request->getAttribute('member_id');
        $p['user_medication_id'] = $request->getAttribute('user_medication_id');
        $func->data_check = ['member_id'=>$p['member_id']];
        
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        $rs = $func->callMethod($p);
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });
    $app->delete('/userMedications/{member_id:[0-9]+}/{user_medication_id:[0-9]+}', function (Request $request, Response $response) {
        //$p = json_decode($request->getBody(), true);
        $p=[];
        $p['method'] = 'remove_user_medications';
        
        $func = new Middleware();

        $p['member_id'] = $request->getAttribute('member_id');
        $p['user_medication_id'] = $request->getAttribute('user_medication_id');
        $func->data_check = ['member_id'=>$p['member_id']];
        
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        $rs = $func->callMethod($p);
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    }); 
    $app->delete('/userStatusMedications/{member_id:[0-9]+}/{user_medication_id:[0-9]+}', function (Request $request, Response $response) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'update_status_medication';
        
        $func = new Middleware();
        
        $p['member_id'] = $request->getAttribute('member_id');
        $p['user_medication_id'] = $request->getAttribute('user_medication_id');
        $func->data_check = ['member_id'=>$p['member_id']];
        
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        $rs = $func->callMethod($p);
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });
    $app->get('/myMedications/{member_id:[0-9]+}', function (Request $request, Response $response, $args) {
        $p['method'] = 'list_my_medications'; 
        $func = new Middleware();

        $p['member_id'] = $args['member_id'];
        $func->data_check = ['member_id'=>$p['member_id']];

        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        return $response->withJSON($func->callMethod($p)['v']);
    });
    $app->get('/myOldMedications/{member_id:[0-9]+}', function (Request $request, Response $response, $args) {
        $p['method'] = 'list_my_old_medications'; 
        $func = new Middleware();

        $p['member_id'] = $args['member_id'];
        $func->data_check = ['member_id'=>$p['member_id']];

        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        return $response->withJSON($func->callMethod($p)['v']);
    });
    $app->get('/myMedicines/{member_id:[0-9]+}', function (Request $request, Response $response, $args) {
        $p['method'] = 'list_my_medicines'; 
        $func = new Middleware();

        $p['member_id'] = $args['member_id'];
        $func->data_check = ['member_id'=>$p['member_id']];

        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        return $response->withJSON($func->callMethod($p)['v']);
    });
    $app->get('/headaches/members/{member_id}[/{ym}]', function (Request $request, Response $response, $args) {
        $p = $args;
        $p['method'] = 'list_headaches';
        $func = new Middleware();

        $func->data_check = ['member_id'=>$p['member_id']];

        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });
    $app->get('/headaches/{member_id}/{start_date}[/{stop_date}]', function (Request $request, Response $response, $args) {
        $p = $args;
        $p['method'] = 'list_member_headaches';
        $func = new Middleware();

        $func->data_check = ['member_id'=>$p['member_id']];

        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });
    $app->post('/headaches', function (Request $request, Response $response) {
        $p = json_decode($request->getBody(), true);

        $p['method'] = 'add_headache_scores';
        $func = new Middleware();

        $func->data_check = ['member_id'=>$p['member_id']];

        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });
    $app->get('/headaches/members/{member_id}/prev/{day}', function (Request $request, Response $response, $args) {
        $p = $args;
        $p['method'] = 'headache_history';
        $func = new Middleware();

        $func->data_check = ['member_id'=>$p['member_id']];

        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    }); 
    $app->get('/medicines/members/{member_id}/prev/{day}', function (Request $request, Response $response, $args) {
        $p = $args;
        $p['method'] = 'medicine_history';
        $func = new Middleware();

        $func->data_check = ['member_id'=>$p['member_id']];

        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });
    $app->get('/triggers/members/{member_id}', function (Request $request, Response $response, $args) {
        $p = $args;
        $p['method'] = 'trigger_member';
        $func = new Middleware();

        $func->data_check = ['member_id'=>$p['member_id']];

        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });
    $app->get('/trigger_advice/{trigger_id}', function (Request $request, Response $response, $args) {
        $p = $args;
        $p['method'] = 'trigger_advice';
        $func = new Middleware();
        // $func->data_check = ['member_id'=>$p['member_id']];
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });
    $app->get('/medication_advice/{medication_id}', function (Request $request, Response $response, $args) {
        $p = $args;
        $p['method'] = 'medication_advice';
        $func = new Middleware();
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });
    $app->get('/triggers/members/{member_id}/prev/{day}', function (Request $request, Response $response, $args) {
        // print_r('*****');
        
        $p = $args;
        $p['method'] = 'trigger_history';
        $func = new Middleware();

        $func->data_check = ['member_id'=>$p['member_id']];

        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });
    $app->get('/viewHeadaches/{headache_score_id:[0-9]+}/{member_id:[0-9]+}', function (Request $request, Response $response, $args) {
        $p = $args;
        $p['method'] = 'view_headaches';
        $func = new Middleware();

        $func->data_check = ['member_id'=>$p['member_id']];

        $func->response = $response;
        $func->preCall($p);
        //print_r($func);exit;
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        //$p['member_id'] = $func->token['token_data']['member_id'];
        $rs = $func->callMethod($p);
        
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });
    $app->delete('/headaches/{headache_score_id:[0-9]+}/{member_id:[0-9]+}', function (Request $request, Response $response) {

        $p['method'] = 'remove_headache_scores';
        $p['member_id'] = $request->getAttribute('member_id');
        $p['headache_score_id'] = $request->getAttribute('headache_score_id');
        $func = new Middleware();

        $func->data_check = ['member_id'=>$p['member_id']];

        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        $rs = $func->callMethod($p);
        
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });
    $app->get('/druginformation/{medicines_id:[0-9]+}', function (Request $request, Response $response,$args) {
        $p = $args;
        $p['method'] = 'drug_information'; 
        $func = new Middleware();

        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        return $response->withJSON($func->callMethod($p)['v']);
    });  
    $app->get('/migraine/{member_id:[0-9]+}/level/{start_date}[/{stop_date}]', function (Request $request, Response $response, $args) {
        $p = $args;
        $p['method'] = 'get_migraine_level'; 
        $func = new Middleware();

        $func->data_check = ['member_id'=>$p['member_id']];
        
        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        return $response->withJSON($func->callMethod($p)['v']);
    });   

    $app->post('/reportProblem', function (Request $request, Response $response, $args) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'send_mail_report';
        $func = new Middleware();
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        if($rs['c']==0){
                if($rs['v']==null){
                    return $response->withJSON(["data" => [ "data" => ["status_report" => 1] , "status_code"=>200 ]]);
                }else{
                    return $response->withStatus(["data" => [ "data" => ["status_report" => 0] , "status_code"=>200 ]]);
                }
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    }); 

    $app->post('/triggers', function (Request $request, Response $response, $args) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'add_new_triggers';
        $func = new Middleware();
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    }); 
  

    $app->patch('/resetPassword', function (Request $request, Response $response) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'reset_password';
        $func = new Middleware();
        $func->response = $response;
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        $rs = $func->callMethod($p);
        if($rs['v'] === 1){
            return $response->withJSON(["data" => [ "data" => ["status_reset" => 1] , "status_code"=>200 ]]);
        }elseif($rs['v'] === 0){
            return $response->withStatus(["data" => [ "data" => ["status_reset" => 0] , "status_code"=>200 ]]);
        }
    });
    $app->get('/dailyNew',function(Request $request, Response $response){
        $p['method'] = 'daily_new'; 
        $func = new Middleware();

        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        return $response->withJSON($func->callMethod($p)['v']);
    });
    $app->post('/migrainCommunity', function (Request $request, Response $response) {
        $p = json_decode($request->getBody(), true);

        $p['method'] = 'add_migraincomdata';
        $func = new Middleware();

        // $func->data_check = ['member_id'=>$p['member_id']];

        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });
    $app->get('/migrainCommunity[/{mcom_id}]', function (Request $request, Response $response, $args) {
        $p['method'] = 'list_migraincommunity'; 
        $func = new Middleware();

        if(isset($args['mcom_id'])){
            $p['mcom_id'] = $args['mcom_id'];
            $func->data_check = ['mcom_id'=>$p['mcom_id']];
        }

        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        return $response->withJSON($func->callMethod($p)['v']);
    }); 
    $app->post('/consultations', function (Request $request, Response $response) {
        $p = json_decode($request->getBody(), true);
     

        $p['method'] = 'create_consultroom';
        $func = new Middleware();

        $func->data_check = ['member_id'=>$p['member_id']];
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });  
    $app->get('/admins/page/{page:[0-9]+}', function (Request $request, Response $response, $args) {
        $p = $args;
        $p['method'] = 'list_admins'; 
        $func = new Middleware();

        if(isset($args['member_id'])){
            $p['member_id'] = $args['member_id'];
            $func->data_check = ['member_id'=>$p['member_id']];
        }

        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        return $response->withJSON($func->callMethod($p)['v']);
    }); 
    $app->patch('/admins/{member_id}', function (Request $request, Response $response) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'set_admin';
        $func = new Middleware();
        $p['member_id'] = $request->getAttribute('member_id');
        $func->data_check = ['member_id'=>$p['member_id']];
        
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });
    $app->post('/admins/search', function (Request $request, Response $response, $args) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'search_admins'; 
        $func = new Middleware();

        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });
    $app->post('/members/search', function (Request $request, Response $response, $args) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'search_members'; 
        $func = new Middleware();

        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        //return $response->withJSON($func->callMethod($p)['v']);
        $rs = $func->callMethod($p);
        
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });
    $app->get('/members/page/{page:[0-9]+}', function (Request $request, Response $response, $args) {
        $p = $args;
        $p['method'] = 'list_members'; 
        $func = new Middleware();

        if(isset($args['member_id'])){
            $p['member_id'] = $args['member_id'];
            $func->data_check = ['member_id'=>$p['member_id']];
        }

        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        return $response->withJSON($func->callMethod($p)['v']);
    });
    // medicines
    $app->get('/medicines/page/{page:[0-9]+}', function (Request $request, Response $response, $args) {
        $p = $args;
        $p['method'] = 'list_medicines'; 
        $func = new Middleware();

        if(isset($args['member_id'])){
            $p['member_id'] = $args['member_id'];
            $func->data_check = ['member_id'=>$p['member_id']];
        }

        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        return $response->withJSON($func->callMethod($p)['v']);
    }); 
    $app->get('/medicines/{medicines_id:[0-9]+}', function (Request $request, Response $response, $args) {
        $p = $args;
        $p['method'] = 'list_medicines'; 
        $func = new Middleware();

        if(isset($args['member_id'])){
            $p['member_id'] = $args['member_id'];
            $func->data_check = ['member_id'=>$p['member_id']];
        }

        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        return $response->withJSON($func->callMethod($p)['v']);
    }); 
    $app->patch('/medicines/{medicines_id}', function (Request $request, Response $response) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'update_medicines';
        
        $func = new Middleware();

        $p['medicines_id'] = $request->getAttribute('medicines_id');
        // $func->data_check = ['member_id'=>$p['member_id']];
        
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        $rs = $func->callMethod($p);
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });
    $app->post('/medicines', function (Request $request, Response $response) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'add_medicines';
        // print_r($p);exit;
        $func = new Middleware();
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        $rs = $func->callMethod($p);
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });
    // daily new
    $app->get('/dailynews/page/{page:[0-9]+}', function (Request $request, Response $response, $args) {
        $p = $args;
        $p['method'] = 'list_dailynews'; 
        $func = new Middleware();

        if(isset($args['dailynews_id'])){
            $p['dailynews_id'] = $args['dailynews_id'];
            $func->data_check = ['dailynews_id'=>$p['dailynews_id']];
        }

        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        return $response->withJSON($func->callMethod($p)['v']);
    }); 
    $app->get('/dailynews/{dailynews_id:[0-9]+}', function (Request $request, Response $response,$args) {
        $p = $args;
        $p['method'] = 'list_dailynews'; 
        $func = new Middleware();

        // if(isset($args['dailynews_id'])){
        //     $p['dailynews_id'] = $args['dailynews_id'];
        //     $func->data_check = ['dailynews_id'=>$p['dailynews_id']];
        // }

        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        return $response->withJSON($func->callMethod($p)['v']);
    }); 
    $app->delete('/dailynews/{dailynews_id:[0-9]+}', function (Request $request, Response $response,$args) {
        $p = $args;
        $p['method'] = 'delete_dailynews'; 
        $func = new Middleware();
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        return $response->withJSON($func->callMethod($p));
    }); 
    $app->post('/dailynews', function (Request $request, Response $response) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'add_dailynews';
        // print_r($p);exit;
        $func = new Middleware();
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        $rs = $func->callMethod($p);
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });
    $app->patch('/dailynews/{dailynews_id}', function (Request $request, Response $response) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'update_dailynews';
        $func = new Middleware();
        $p['dailynews_id'] = $request->getAttribute('dailynews_id');
        
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        $rs = $func->callMethod($p);
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });

    $app->patch('/update_triggers/{triggers_id:[0-9]+}', function (Request $request, Response $response) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'update_trigger';
        $func = new Middleware();
        $p['triggers_id'] = $request->getAttribute('triggers_id');
        
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });
    $app->delete('/delete_triggers/{triggers_id}', function (Request $request, Response $response) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'update_trigger';
        $p['status'] = 0;
        $func = new Middleware();
        $p['triggers_id'] = $request->getAttribute('triggers_id');
        
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        $rs = $func->callMethod($p);
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });

    $app->get('/getFrequencyPain/{member_id:[0-9]+}/prev/{day}', function (Request $request, Response $response, $args) {
        $p = $args;
        $p['method'] = 'get_frequency_pain'; 
        $func = new Middleware();

        $func->data_check = ['member_id'=>$p['member_id']];
        
        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        // return $response->withJSON($func->callMethod($p));
        return $response->withJSON($func->callMethod($p)['v']);
    });   

    $app->get('/getFrequencyTrigger/{member_id:[0-9]+}/prev/{day}', function (Request $request, Response $response, $args) {
        $p = $args;
        $p['method'] = 'get_frequency_trigger'; 
        $func = new Middleware();

        $func->data_check = ['member_id'=>$p['member_id']];
        
        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        // return $response->withJSON($func->callMethod($p));
        return $response->withJSON($func->callMethod($p)['v']);
    });   
    $app->get('/getFrequencyCoSymptom/{member_id:[0-9]+}/prev/{day}', function (Request $request, Response $response, $args) {
        $p = $args;
        $p['method'] = 'get_frequency_coSymptom'; 
        $func = new Middleware();

        $func->data_check = ['member_id'=>$p['member_id']];
        
        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        // return $response->withJSON($func->callMethod($p));
        return $response->withJSON($func->callMethod($p)['v']);
    });   
    $app->get('/getFrequencyMedication/{member_id:[0-9]+}/prev/{day}', function (Request $request, Response $response, $args) {
        $p = $args;
        $p['method'] = 'get_frequency_medication'; 
        $func = new Middleware();

        $func->data_check = ['member_id'=>$p['member_id']];
        
        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        // return $response->withJSON($func->callMethod($p));
        return $response->withJSON($func->callMethod($p)['v']);
    });   
    $app->get('/upFirebase/{member_id:[0-9]+}', function (Request $request, Response $response) {
        $p['method'] = 'test'; 
        $p['member_id'] = $request->getAttribute('member_id');
        $func = new Middleware();
        
        $func->data_check = ['member_id'=>$p['member_id']];
        
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        // return $response->withJSON($func->callMethod($p));
        return $response->withJSON($func->callMethod($p)['v']);
    });   
    $app->post('/purchase', function (Request $request, Response $response) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'add_purchase';
        // print_r($p);exit;
        $func = new Middleware();
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });
    $app->get('/logs/{member_id:[0-9]+}', function (Request $request, Response $response) {
        $p['method'] = 'get_logs'; 

        $p['member_id'] = $request->getAttribute('member_id');
        $func = new Middleware();
        
        $func->data_check = ['member_id'=>$p['member_id']];
        
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        // return $response->withJSON($func->callMethod($p));
        return $response->withJSON($func->callMethod($p)['v']);
    });   
    $app->get('/report_pdf/{member_id:[0-9]+}/{day}', function (Request $request, Response $response) {
        $p['method'] = 'pdf_report'; 
        // $p['method'] = 'pdf_report1'; 
        $p['member_id'] = $request->getAttribute('member_id');
        $p['day'] = $request->getAttribute('day');
        $func = new Middleware();
        $func->data_check = ['member_id'=>$p['member_id']];
        
        header('Content-Type: application/json');
        // echo json_encode($data)."</br>" ."</br>";
        $func->response =  $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        // return $response->withJSON($func->callMethod($p));
        return $response->withJSON($func->callMethod($p)['v']);
    });   
    $app->get('/report_pdf1/{member_id:[0-9]+}/{day}', function (Request $request, Response $response) {
        // $p['method'] = 'pdf_report'; 
        $p['method'] = 'pdf_report1'; 
        $p['member_id'] = $request->getAttribute('member_id');
        $p['day'] = $request->getAttribute('day');
        $func = new Middleware();
        $func->data_check = ['member_id'=>$p['member_id']];
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        // return $response->withJSON($func->callMethod($p));
        return $response->withJSON($func->callMethod($p)['v']);
    });   
    $app->post('/mail_check',function(Request $request, Response $response,$args){
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'get_mail_check'; 
        $func = new Middleware();
        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        return $response->withJSON($func->callMethod($p)['v']);
    });
    $app->patch('/local_language',function(Request $request, Response $response,$args){
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'local_language';
        $func = new Middleware();
        $func->data_check = ['member_id'=>$p['member_id']];
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }

    });
    // $app->delete('/logout/{member_id:[0-9]+}',function(Request $request,Response $response,$args){
    //     $p = json_decode($request->getBody(),true);
    //     $p['method'] = 'logout';
    //     $func = new Middleware();
    //     $p['member_id'] = $request->getAttribute('member_id');
    //     $func->data_check = ['member_id'=>$p['member_id']];
    //     $func->response = $response;
    //     $func->preCall($p);
    //     $func->response = $response;
    //     $func->preCall($p);
    //     if(!$func->token['valid']){
    //         return $func->afterCall(401);
    //     }

    //     $rs = $func->callMethod($p);
    //     if($rs['c']==0){
    //         return $response->withJSON($rs['v']);
    //     }else{
    //         return $response->withStatus($rs['c'])
    //         ->withHeader('Content-Type', 'text/html')
    //         ->write($rs['e']);
    //     }
    //     // return $response->withJSON($func->callMethod($p));
    //     return $response->withJSON($func->callMethod($p));
    // });

    
});

$app->group('/v4',function() use($app){
    $app->get('/testV3',function(Request $request, Response $response, $args){
                print_r('***V4***');
        return ;
    });
    // THIS FOR CALL DATA IN FIREBASE
    $app->post('/check_notification', function (Request $request, Response $response,$args) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'get_notification_token'; 
    
        $func = new MiddlewareV4();
        $func->data_check = ['member_id'=>$p['member_id']];
        
        $func->response = $response;
        // $func->preCall($p);

        // if(!$func->token['valid']){
        //     return $func->afterCall(401);
        // }

        return $response->withJSON($func->callMethod($p)['v']);
    });
    $app->post('/notification', function (Request $request, Response $response,$args) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'send_notification';
        $func = new MiddlewareV4();
        // $func->data_check = ['member_id'=>4796];
        $func->data_check = ['member_id'=>$p['member_id']];
        $func->response = $response;
        $func->preCall($p);
        $func->callMethod($p);
        
    });  
    $app->patch('/notification', function (Request $request, Response $response,$args) {
        $p = json_decode($request->getBody(), true);
        
        $p['method'] = 'set_notification';
        $headers = getAuthorizationHeader();
        $token_data  =  explode(" ",  $headers); 
        $p['token'] = $token_data[1]  ;
        $func = new MiddlewareV4();
        $func->data_check = ['member_id'=>$p['member_id']];
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
       
    });  
    $app->post('/admin/noti/{member_id:[0-9]+}', function (Request $request, Response $response,$args) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'notification_send';
        $func = new MiddlewareV4();
        $func->data_check = ['member_id'=>$p['member_id']];
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });  
    $app->post('/comment', function (Request $request, Response $response,$args) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'firestore_comment';
        $func = new MiddlewareV4();
        $func->data_check = ['member_id'=>$p['member_id']];
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });  
    $app->get('/list_comment/{post_id}/{member_id:[0-9]+}',function(Request $request, Response $response,$args){
        $post_id = $request->getAttribute('post_id');
        $member_id = $request->getAttribute('member_id');
        $p['member_id'] = $member_id;
        $p['post_id'] = $post_id;
        
        $p['method'] = 'firestore_listcomment'; 
        $func = new MiddlewareV4();

        $func->data_check = ['member_id'=>$p['member_id']];
        
        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        return $response->withJSON($func->callMethod($p)['v']);
    });
    $app->get('/list_post/{member_id:[0-9]+}',function(Request $request, Response $response,$args){
        $member_id = $request->getAttribute('member_id');
        $p['method'] = 'firestore_listpost'; 
        $p['member_id'] = $member_id;
        $func = new MiddlewareV4();

        $func->data_check = ['member_id'=>$p['member_id']];
        
        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        return $response->withJSON($func->callMethod($p)['v']);
    });

    $app->get('/last_post',function(Request $request, Response $response,$args){
        $member_id = $request->getAttribute('member_id');
        
        $p['method'] = 'firestore_lastpost'; 
        $p['member_id'] = $member_id;
        $func = new MiddlewareV4();

        $func->data_check = ['member_id'=>$p['member_id']];
        
        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        return $response->withJSON($func->callMethod($p)['v']);
    });
    $app->get('/chatRooms',function(Request $request, Response $response,$args){
        $p['method'] = 'firestore_chatrooms'; 
        $func = new MiddlewareV4();
        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        return $response->withJSON($func->callMethod($p)['v']);
    });
    $app->post('/likepost', function (Request $request, Response $response,$args) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'firestore_likepost';
        $func = new MiddlewareV4();
        $func->data_check = ['member_id'=>$p['member_id']];
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });  
    $app->post('/likecomment', function (Request $request, Response $response,$args) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'firestore_likecomment';
        $func = new MiddlewareV4();
        $func->data_check = ['member_id'=>$p['member_id']];
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });  
    $app->post('/setnewchatrooms', function (Request $request, Response $response,$args) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'firestore_newchatroom';
        $func = new MiddlewareV4();
        $func->data_check = ['member_id'=>$p['member_id']];
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });  

    $app->get('/purchasing/members/{member_id:[0-9]+}', function (Request $request, Response $response, $args) {
        $p['method'] = 'list_purchase_history'; 
        $func = new MiddlewareV4();

        $p['member_id'] = $args['member_id'];
        $func->data_check = ['member_id'=>$p['member_id']];
        
        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        return $response->withJSON($func->callMethod($p)['v']);
    });

     $app->get('/getFirestore',function(Request $request, Response $response){
        $p['method']='firestore';
        $func = new MiddlewareV4();
        $func->response = $response;
        $func->preCall($p);
        $rs = $func->callMethod($p);
        // return $response->withJSON($rs);
    });
    $app->get('/jwt/{n:[0-9]+}', function (Request $request, Response $response, $args) {
        $n = $request->getAttribute('n') * 1;
        $p['method']='jwt';
        $config = new Config();
        $cf = $config->cf;
        $jwt = $cf['jwt']['smapi'];
        $auth=new Auth($jwt);
        print_r($auth->setAuth(['group'=>$n,'member_id'=>'1']));
    });
    $app->get('/jwt/t/{token}', function (Request $request, Response $response, $args) {
        $token = $request->getAttribute('token');
        $p['method']='jwt';

        $config = new Config();
        $cf = $config->cf;
        $jwt = $cf['jwt']['smapi'];
        /*
        $log = new Log();
        $log_id = $log->saveLog($p);
        */
        $auth=new Auth($jwt);
        $auth_result = $auth->checkAuthManual($token);
        // print_r($auth_result);exit;
        if($auth_result['valid']){
            include "servicesV4/".$p['method'].".php";
            $p['token_data'] = $auth_result['token_data'];
            $rs = $response->withJSON(call_user_func($p['method'], $p));

            if($log_id>0){
                $log->updateLog($log_id,$rs);
            }
            return $rs;
        }
    });
    $app->post('/authentications', function (Request $request, Response $response, $args) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'authentications';
        $func = new MiddlewareV4();
        
        $func->response = $response;
        $func->preCall($p);
        $rs = $func->callMethod($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    }); 
    $app->post('/config', function (Request $request, Response $response) {
        $p = json_decode($request->getBody(), true);

        $p['method'] = 'set_config';
        $func = new MiddlewareV4();

        $func->data_check = ['member_id'=>$p['member_id']];

        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    }); 
    $app->get('/triggers/{member_id:[0-9]+}',function(Request $request, Response $response,$args){
        $p['method'] = 'list_triggers'; 
        $func = new MiddlewareV4();
        if(isset($args['member_id'])){
            $p['member_id'] = $args['member_id'];
            $func->data_check = ['member_id'=>$p['member_id']];
        }
         $headers = getAuthorizationHeader();
         $token_data  =  explode(" ",  $headers); 
         $p['token'] = $token_data[1]  ;
        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        return $response->withJSON($func->callMethod($p)['v']);
    });
    $app->get('/favorite_triggers/{member_id:[0-9]+}',function(Request $request, Response $response,$args){
        $p['method'] = 'favorite_triggers'; 
        $func = new MiddlewareV4();
        if(isset($args['member_id'])){
            $p['member_id'] = $args['member_id'];
            $func->data_check = ['member_id'=>$p['member_id']];
        }
         $headers = getAuthorizationHeader();
         $token_data  =  explode(" ",  $headers); 
         $p['token'] = $token_data[1]  ;
        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        return $response->withJSON($func->callMethod($p)['v']);
    });


    $app->get('/triggers',function(Request $request, Response $response,$args){
        $p['method'] = 'list_all_triggers'; 
        $headers = getAuthorizationHeader();
        if (!empty($headers)) {
            if (preg_match('/Bearer\s(\S+)/', $headers, $matches)) {
                 
                $config = new Config();
                $cf = $config->cf;
                $jwt = $cf['jwt']['smapi'];
             
                $auth=new Auth($jwt);
                $auth_result = $auth->checkAuthManual($matches[1]);
                $p['token_data']  = $auth_result['token_data'] ; 
                
            }
        }
        // $headers = getAuthorizationHeader();
        $token_data  =  explode(" ",  $headers); 
        $p['token'] = $token_data[1]  ;
        $func = new MiddlewareV4();
        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        return $response->withJSON($func->callMethod($p)['v']);
    });

    $app->post('/register', function (Request $request, Response $response) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'regis_member';
        $func = new MiddlewareV4();

        $func->response = $response;
        $func->preCall($p);

        $rs = $func->callMethod($p);
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    }); 
    $app->post('/members', function (Request $request, Response $response) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'add_member';
        $func = new MiddlewareV4();

        $func->response = $response;
        $func->preCall($p);

        $rs = $func->callMethod($p);
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    }); 
    $app->post('/login', function (Request $request, Response $response) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'login';
        $func = new MiddlewareV4();

        $func->response = $response;
        $func->preCall($p);

        $rs = $func->callMethod($p);
        
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });
    $app->get('/symptoms[/{language}]',function(Request $request, Response $response){
        $p['language'] = $request->getAttribute('language');
        $p['method'] = 'list_symptoms'; 
        $headers = getAuthorizationHeader();
        if (!empty($headers)) {
            if (preg_match('/Bearer\s(\S+)/', $headers, $matches)) {
                 
                $config = new Config();
                $cf = $config->cf;
                $jwt = $cf['jwt']['smapi'];
             
                $auth=new Auth($jwt);
                $auth_result = $auth->checkAuthManual($matches[1]);
                $p['token_data']  = $auth_result['token_data'] ; 
                
            }
        }
        $token_data  =  explode(" ",  $headers); 
        $p['token'] = $token_data[1]  ;
        $p['member_id'] = $p['token_data']['member_id'];
        // print_r($p);
        $func = new MiddlewareV4();
        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        return $response->withJSON($func->callMethod($p)['v']);
    });

    $app->get('/members[/{member_id}]', function (Request $request, Response $response, $args) {
        $p['method'] = 'list_members'; 
        $func = new MiddlewareV4();

        if(isset($args['member_id'])){
            $p['member_id'] = $args['member_id'];
            $func->data_check = ['member_id'=>$p['member_id']];
        }

        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        return $response->withJSON($func->callMethod($p)['v']);
    }); 
    $app->patch('/members/{member_id:[0-9]+}', function (Request $request, Response $response) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'update_member';
        $headers = getAuthorizationHeader();
        $token_data  =  explode(" ",  $headers); 
        $p['token'] = $token_data[1]  ;
        $func = new MiddlewareV4();
        
        $p['member_id'] = $request->getAttribute('member_id');
        $func->data_check = ['member_id'=>$p['member_id']];
        
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        $rs = $func->callMethod($p);
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs)
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });

    $app->post('/userMedications', function (Request $request, Response $response) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'add_user_medications';
        $func = new MiddlewareV4();

        $func->data_check = ['member_id'=>$p['member_id']];

        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        
        if($rs['c']==0){
            return $response->withJSON($rs);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });
    $app->get('/userMedications/{member_id:[0-9]+}/{user_medication_id:[0-9]+}', function (Request $request, Response $response,$args) {
        $p['method'] = 'list_user_medications'; 
        $func = new MiddlewareV4();

        if(isset($args['user_medication_id'])){
            $p['user_medication_id'] = $args['user_medication_id'];
            $p['member_id'] = $args['member_id'];
            $func->data_check = ['member_id'=>$p['member_id']];
        }

        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        return $response->withJSON($func->callMethod($p)['v']);
    });
    $app->patch('/userMedications/{member_id:[0-9]+}/{user_medication_id:[0-9]+}', function (Request $request, Response $response,$args) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'update_medication';
        $func = new MiddlewareV4();
        
        $p['member_id'] = $request->getAttribute('member_id');
        $p['user_medication_id'] = $request->getAttribute('user_medication_id');
        $func->data_check = ['member_id'=>$p['member_id']];
        
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        $rs = $func->callMethod($p);
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });
    $app->delete('/userMedications/{member_id:[0-9]+}/{user_medication_id:[0-9]+}', function (Request $request, Response $response) {
        //$p = json_decode($request->getBody(), true);
        $p=[];
        $p['method'] = 'remove_user_medications';
        
        $func = new MiddlewareV4();

        $p['member_id'] = $request->getAttribute('member_id');
        $p['user_medication_id'] = $request->getAttribute('user_medication_id');
        $func->data_check = ['member_id'=>$p['member_id']];
        
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        $rs = $func->callMethod($p);
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    }); 
    $app->delete('/userStatusMedications/{member_id:[0-9]+}/{user_medication_id:[0-9]+}', function (Request $request, Response $response) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'update_status_medication';
        
        $func = new MiddlewareV4();
        
        $p['member_id'] = $request->getAttribute('member_id');
        $p['user_medication_id'] = $request->getAttribute('user_medication_id');
        $func->data_check = ['member_id'=>$p['member_id']];
        
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        $rs = $func->callMethod($p);
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });
    $app->get('/myMedications/{member_id:[0-9]+}', function (Request $request, Response $response, $args) {
        $p['method'] = 'list_my_medications'; 
        $func = new MiddlewareV4();

        $p['member_id'] = $args['member_id'];
        $func->data_check = ['member_id'=>$p['member_id']];

        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        return $response->withJSON($func->callMethod($p)['v']);
    });
    $app->get('/myOldMedications/{member_id:[0-9]+}', function (Request $request, Response $response, $args) {
        $p['method'] = 'list_my_old_medications'; 
        $func = new MiddlewareV4();

        $p['member_id'] = $args['member_id'];
        $func->data_check = ['member_id'=>$p['member_id']];

        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        return $response->withJSON($func->callMethod($p)['v']);
    });
    $app->get('/myMedicines/{member_id:[0-9]+}', function (Request $request, Response $response, $args) {
        $p['method'] = 'list_my_medicines'; 
        $func = new MiddlewareV4();

        $p['member_id'] = $args['member_id'];
        $func->data_check = ['member_id'=>$p['member_id']];

        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        return $response->withJSON($func->callMethod($p)['v']);
    });
    $app->get('/headaches/members/{member_id}[/{ym}]', function (Request $request, Response $response, $args) {
        $p = $args;
        $p['method'] = 'list_headaches';
        $func = new MiddlewareV4();

        $func->data_check = ['member_id'=>$p['member_id']];

        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });
    $app->get('/headaches/{member_id}/{start_date}[/{stop_date}]', function (Request $request, Response $response, $args) {
        $p = $args;
        $p['method'] = 'list_member_headaches';
        $func = new MiddlewareV4();

        $func->data_check = ['member_id'=>$p['member_id']];

        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });
    $app->get('/listViewHeadaches/{member_id}/prev/{day}', function (Request $request, Response $response, $args) {
        $p = $args;
        $p['method'] = 'list_view_headaches';
        $headers = getAuthorizationHeader();
        $token_data  =  explode(" ",  $headers); 
        $p['token'] = $token_data[1]  ;
        $func = new MiddlewareV4();

        $func->data_check = ['member_id'=>$p['member_id']];

        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });
    $app->post('/headaches', function (Request $request, Response $response) {
        $p = json_decode($request->getBody(), true);

        // print_r($p);
        $p['method'] = 'add_headache_scores';
        $func = new MiddlewareV4();

        $func->data_check = ['member_id'=>$p['member_id']];

        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });
    $app->get('/headaches/members/{member_id}/prev/{day}', function (Request $request, Response $response, $args) {
        $p = $args;
        $p['method'] = 'headache_history';
        $func = new MiddlewareV4();

        $func->data_check = ['member_id'=>$p['member_id']];

        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    }); 
    $app->get('/medicines/members/{member_id}/prev/{day}', function (Request $request, Response $response, $args) {
        $p = $args;
        $p['method'] = 'medicine_history';
        $func = new MiddlewareV4();

        $func->data_check = ['member_id'=>$p['member_id']];

        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });
    // $app->get('/triggers/members/{member_id}', function (Request $request, Response $response, $args) {
    //     $p = $args;
    //     $p['method'] = 'trigger_member';
    //     $func = new MiddlewareV4();

    //     $func->data_check = ['member_id'=>$p['member_id']];

    //     $func->response = $response;
    //     $func->preCall($p);
    //     if(!$func->token['valid']){
    //         return $func->afterCall(401);
    //     }
    //     $rs = $func->callMethod($p);
        
    //     if($rs['c']==0){
    //         return $response->withJSON($rs['v']);
    //     }else{
    //         return $response->withStatus($rs['c'])
    //         ->withHeader('Content-Type', 'text/html')
    //         ->write($rs['e']);
    //     }
    // });
    $app->get('/trigger_advice/{trigger_id}', function (Request $request, Response $response, $args) {
        $p = $args;
        $p['method'] = 'trigger_advice';
        $func = new MiddlewareV4();
        // $func->data_check = ['member_id'=>$p['member_id']];
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });
    $app->get('/medication_advice/{medication_id}', function (Request $request, Response $response, $args) {
        $p = $args;
        $p['method'] = 'medication_advice';
        $func = new MiddlewareV4();
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });
    $app->get('/triggers/members/{member_id}/prev/{day}', function (Request $request, Response $response, $args) {
        
        $p = $args;
        $p['method'] = 'trigger_history';
        $headers = getAuthorizationHeader();
        $token_data  =  explode(" ",  $headers); 
        $p['token'] = $token_data[1]  ;
        $func = new MiddlewareV4();

        $func->data_check = ['member_id'=>$p['member_id']];

        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });
    $app->get('/viewHeadaches/{headache_score_id:[0-9]+}/{member_id:[0-9]+}', function (Request $request, Response $response, $args) {
        $p = $args;
        $p['method'] = 'view_headaches';
        $headers = getAuthorizationHeader();
        $token_data  =  explode(" ",  $headers); 
        $p['token'] = $token_data[1]  ;
        $func = new MiddlewareV4();

        $func->data_check = ['member_id'=>$p['member_id']];

        $func->response = $response;
        $func->preCall($p);
        //print_r($func);exit;
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        //$p['member_id'] = $func->token['token_data']['member_id'];
        $rs = $func->callMethod($p);
        
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });
    $app->delete('/headaches/{headache_score_id:[0-9]+}/{member_id:[0-9]+}', function (Request $request, Response $response) {

        $p['method'] = 'remove_headache_scores';
        $p['member_id'] = $request->getAttribute('member_id');
        $p['headache_score_id'] = $request->getAttribute('headache_score_id');
        $func = new MiddlewareV4();

        $func->data_check = ['member_id'=>$p['member_id']];

        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        $rs = $func->callMethod($p);
        
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });
    $app->get('/druginformation/{medicines_id:[0-9]+}', function (Request $request, Response $response,$args) {
        $p = $args;
        $p['method'] = 'drug_information'; 
        $func = new MiddlewareV4();

        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        return $response->withJSON($func->callMethod($p)['v']);
    });  
    $app->get('/migraine/{member_id:[0-9]+}/level/{start_date}[/{stop_date}]', function (Request $request, Response $response, $args) {
        $p = $args;
        $p['method'] = 'get_migraine_level'; 
        $headers = getAuthorizationHeader();
        $token_data  =  explode(" ",  $headers); 
        $p['token'] = $token_data[1]  ;
        $func = new MiddlewareV4();

        $func->data_check = ['member_id'=>$p['member_id']];
        
        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        return $response->withJSON($func->callMethod($p)['v']);
    });   

    $app->post('/reportProblem', function (Request $request, Response $response, $args) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'send_mail_report';
        $func = new MiddlewareV4();
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        if($rs['c']==0){
                if($rs['v']==null){
                    return $response->withJSON(["data" => [ "data" => ["status_report" => 1] , "status_code"=>200 ]]);
                }else{
                    return $response->withStatus(["data" => [ "data" => ["status_report" => 0] , "status_code"=>200 ]]);
                }
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    }); 

    $app->post('/triggers', function (Request $request, Response $response, $args) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'add_new_triggers';
        $headers = getAuthorizationHeader();
        $token_data  =  explode(" ",  $headers); 
        $p['token'] = $token_data[1]  ;
        $func = new MiddlewareV4();
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    }); 
    $app->post('/broadcasts', function (Request $request, Response $response, $args) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'get_user_broadcasts';
        $func = new MiddlewareV4();
        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        return $response->withJSON($func->callMethod($p));
    }); 
    $app->post('/send_broadcasts', function (Request $request, Response $response, $args) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'send_broadcasts';
        $func = new MiddlewareV4();
        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        return $response->withJSON($func->callMethod($p));
    }); 
  

    $app->patch('/resetPassword', function (Request $request, Response $response) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'reset_password';
        $func = new MiddlewareV4();
        $func->response = $response;
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        $rs = $func->callMethod($p);
        if($rs['v'] === 1){
            return $response->withJSON(["data" => [ "data" => ["status_reset" => 1] , "status_code"=>200 ]]);
        }elseif($rs['v'] === 0){
            return $response->withStatus(["data" => [ "data" => ["status_reset" => 0] , "status_code"=>200 ]]);
        }
    });
    $app->get('/dailyNew',function(Request $request, Response $response){
        $p['method'] = 'daily_new'; 
        $func = new MiddlewareV4();

        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        return $response->withJSON($func->callMethod($p)['v']);
    });
    $app->post('/migrainCommunity', function (Request $request, Response $response) {
        $p = json_decode($request->getBody(), true);

        $p['method'] = 'add_migraincomdata';
        $func = new MiddlewareV4();

        // $func->data_check = ['member_id'=>$p['member_id']];

        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });
    $app->get('/migrainCommunity[/{mcom_id}]', function (Request $request, Response $response, $args) {
        $p['method'] = 'list_migraincommunity'; 
        $func = new MiddlewareV4();

        if(isset($args['mcom_id'])){
            $p['mcom_id'] = $args['mcom_id'];
            $func->data_check = ['mcom_id'=>$p['mcom_id']];
        }

        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        return $response->withJSON($func->callMethod($p)['v']);
    }); 
    $app->post('/consultations', function (Request $request, Response $response) {
        $p = json_decode($request->getBody(), true);
     

        $p['method'] = 'create_consultroom';
        $func = new MiddlewareV4();

        $func->data_check = ['member_id'=>$p['member_id']];
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });  
    $app->get('/admins/page/{page:[0-9]+}', function (Request $request, Response $response, $args) {
        $p = $args;
        $p['method'] = 'list_admins'; 
        $func = new MiddlewareV4();

        if(isset($args['member_id'])){
            $p['member_id'] = $args['member_id'];
            $func->data_check = ['member_id'=>$p['member_id']];
        }

        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        return $response->withJSON($func->callMethod($p)['v']);
    }); 
    $app->patch('/admins/{member_id}', function (Request $request, Response $response) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'set_admin';
        $func = new MiddlewareV4();
        $p['member_id'] = $request->getAttribute('member_id');
        $func->data_check = ['member_id'=>$p['member_id']];
        
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });
    $app->post('/admins/search', function (Request $request, Response $response, $args) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'search_admins'; 
        $func = new MiddlewareV4();

        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });
    $app->post('/members/search', function (Request $request, Response $response, $args) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'search_members'; 
        $func = new MiddlewareV4();

        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        //return $response->withJSON($func->callMethod($p)['v']);
        $rs = $func->callMethod($p);
        
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });
    $app->get('/members/page/{page:[0-9]+}', function (Request $request, Response $response, $args) {
        $p = $args;
        $p['method'] = 'list_members'; 
        $func = new MiddlewareV4();

        if(isset($args['member_id'])){
            $p['member_id'] = $args['member_id'];
            $func->data_check = ['member_id'=>$p['member_id']];
        }

        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        return $response->withJSON($func->callMethod($p)['v']);
    });
    // medicines
    $app->get('/medicines/page/{page:[0-9]+}', function (Request $request, Response $response, $args) {
        $p = $args;
        $p['method'] = 'list_medicines'; 
        $func = new MiddlewareV4();

        if(isset($args['member_id'])){
            $p['member_id'] = $args['member_id'];
            $func->data_check = ['member_id'=>$p['member_id']];
        }

        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        return $response->withJSON($func->callMethod($p)['v']);
    }); 
    $app->get('/medicines/{medicines_id:[0-9]+}', function (Request $request, Response $response, $args) {
        $p = $args;
        $p['method'] = 'list_medicines'; 
        $func = new MiddlewareV4();

        if(isset($args['member_id'])){
            $p['member_id'] = $args['member_id'];
            $func->data_check = ['member_id'=>$p['member_id']];
        }

        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        return $response->withJSON($func->callMethod($p)['v']);
    }); 
    $app->patch('/medicines/{medicines_id}', function (Request $request, Response $response) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'update_medicines';
        
        $func = new MiddlewareV4();

        $p['medicines_id'] = $request->getAttribute('medicines_id');
        // $func->data_check = ['member_id'=>$p['member_id']];
        
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        $rs = $func->callMethod($p);
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });
    $app->post('/medicines', function (Request $request, Response $response) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'add_medicines';
        // print_r($p);exit;
        $func = new MiddlewareV4();
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        $rs = $func->callMethod($p);
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });
    // daily new
    $app->get('/dailynews/page/{page:[0-9]+}', function (Request $request, Response $response, $args) {
        $p = $args;
        $p['method'] = 'list_dailynews'; 
        $func = new MiddlewareV4();

        if(isset($args['dailynews_id'])){
            $p['dailynews_id'] = $args['dailynews_id'];
            $func->data_check = ['dailynews_id'=>$p['dailynews_id']];
        }

        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        return $response->withJSON($func->callMethod($p)['v']);
    }); 
    $app->get('/dailynews/{dailynews_id:[0-9]+}', function (Request $request, Response $response,$args) {
        $p = $args;
        $p['method'] = 'list_dailynews'; 
        $func = new MiddlewareV4();

        // if(isset($args['dailynews_id'])){
        //     $p['dailynews_id'] = $args['dailynews_id'];
        //     $func->data_check = ['dailynews_id'=>$p['dailynews_id']];
        // }

        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        return $response->withJSON($func->callMethod($p)['v']);
    }); 
    $app->delete('/dailynews/{dailynews_id:[0-9]+}', function (Request $request, Response $response,$args) {
        $p = $args;
        $p['method'] = 'delete_dailynews'; 
        $func = new MiddlewareV4();
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        return $response->withJSON($func->callMethod($p));
    }); 
    $app->post('/dailynews', function (Request $request, Response $response) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'add_dailynews';
        // print_r($p);exit;
        $func = new MiddlewareV4();
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        $rs = $func->callMethod($p);
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });
    $app->patch('/dailynews/{dailynews_id}', function (Request $request, Response $response) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'update_dailynews';
        $func = new MiddlewareV4();
        $p['dailynews_id'] = $request->getAttribute('dailynews_id');
        
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        $rs = $func->callMethod($p);
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });

    $app->patch('/update_triggers/{triggers_id:[0-9]+}', function (Request $request, Response $response) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'update_trigger';
        $func = new MiddlewareV4();
        $p['triggers_id'] = $request->getAttribute('triggers_id');
        
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });
    $app->delete('/delete_triggers/{triggers_id}', function (Request $request, Response $response) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'update_trigger';
        $p['status'] = 0;
        $func = new MiddlewareV4();
        $p['triggers_id'] = $request->getAttribute('triggers_id');
        
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        $rs = $func->callMethod($p);
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });

    $app->get('/getFrequencyPain/{member_id:[0-9]+}/prev/{day}', function (Request $request, Response $response, $args) {
        $p = $args;
        $p['method'] = 'get_frequency_pain'; 
     
        $headers = getAuthorizationHeader();
        $token_data  =  explode(" ",  $headers); 
        $p['token'] = $token_data[1]  ;
        $func = new MiddlewareV4();
        $func->data_check = ['member_id'=>$p['member_id']];
        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        // return $response->withJSON($func->callMethod($p));
        return $response->withJSON($func->callMethod($p)['v']);
    });   

    $app->get('/getFrequencyTrigger/{member_id:[0-9]+}/prev/{day}', function (Request $request, Response $response, $args) {
        $p = $args;
        $p['method'] = 'get_frequency_trigger'; 
        $headers = getAuthorizationHeader();
        $token_data  =  explode(" ",  $headers); 
        $p['token'] = $token_data[1]  ;
        $func = new MiddlewareV4();

        $func->data_check = ['member_id'=>$p['member_id']];
        
        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        // return $response->withJSON($func->callMethod($p));
        return $response->withJSON($func->callMethod($p)['v']);
    });   
    $app->get('/getFrequencyCoSymptom/{member_id:[0-9]+}/prev/{day}', function (Request $request, Response $response, $args) {
        $p = $args;
        $p['method'] = 'get_frequency_coSymptom'; 
        $func = new MiddlewareV4();

        $func->data_check = ['member_id'=>$p['member_id']];
        
        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        // return $response->withJSON($func->callMethod($p));
        return $response->withJSON($func->callMethod($p)['v']);
    });   
    $app->get('/getFrequencyMedication/{member_id:[0-9]+}/prev/{day}', function (Request $request, Response $response, $args) {
        $p = $args;
        $p['method'] = 'get_frequency_medication'; 
        $func = new MiddlewareV4();

        $func->data_check = ['member_id'=>$p['member_id']];
        
        $func->response = $response;
        $func->preCall($p);

        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        // return $response->withJSON($func->callMethod($p));
        return $response->withJSON($func->callMethod($p)['v']);
    });   
    $app->get('/upFirebase/{member_id:[0-9]+}', function (Request $request, Response $response) {
        $p['method'] = 'test'; 
        $p['member_id'] = $request->getAttribute('member_id');
        $func = new MiddlewareV4();
        
        $func->data_check = ['member_id'=>$p['member_id']];
        
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        // return $response->withJSON($func->callMethod($p));
        return $response->withJSON($func->callMethod($p)['v']);
    });   
    $app->post('/purchase', function (Request $request, Response $response) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'add_purchase';
        $headers = getAuthorizationHeader();
        $token_data  =  explode(" ",  $headers); 
        $p['token'] = $token_data[1]  ;
        // print_r($p);exit;
        $func = new MiddlewareV4();
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }
    });
    $app->get('/logs/{member_id:[0-9]+}', function (Request $request, Response $response) {
        $p['method'] = 'get_logs'; 

        $p['member_id'] = $request->getAttribute('member_id');
        $func = new MiddlewareV4();
        
        $func->data_check = ['member_id'=>$p['member_id']];
        
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        // return $response->withJSON($func->callMethod($p));
        return $response->withJSON($func->callMethod($p)['v']);
    });   
    $app->get('/report_pdf/{member_id:[0-9]+}/{day}', function (Request $request, Response $response) {
        $p['method'] = 'pdf_report'; 
        // $p['method'] = 'pdf_report1'; 
        $p['member_id'] = $request->getAttribute('member_id');
        $p['day'] = $request->getAttribute('day');
        $func = new MiddlewareV4();
        $func->data_check = ['member_id'=>$p['member_id']];
        
        header('Content-Type: application/json');
        // echo json_encode($data)."</br>" ."</br>";
        $func->response =  $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        // return $response->withJSON($func->callMethod($p));
        return $response->withJSON($func->callMethod($p)['v']);
    });   
    $app->get('/report_pdf1/{member_id:[0-9]+}/{day}', function (Request $request, Response $response) {
        // $p['method'] = 'pdf_report'; 
        $p['method'] = 'pdf_report1'; 
        $p['member_id'] = $request->getAttribute('member_id');
        $p['day'] = $request->getAttribute('day');
        $func = new MiddlewareV4();
        $func->data_check = ['member_id'=>$p['member_id']];
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        // return $response->withJSON($func->callMethod($p));
        return $response->withJSON($func->callMethod($p)['v']);
    });   
    $app->post('/mail_check',function(Request $request, Response $response,$args){
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'get_mail_check'; 
        $func = new MiddlewareV4();
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        // print_r($p);

        return $response->withJSON($func->callMethod($p)['v']);
    });
    $app->post('/local_language', function (Request $request, Response $response,$args) {
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'get_local_language'; 
    
        $func = new MiddlewareV4();
        $func->data_check = ['member_id'=>$p['member_id']];
        
        $func->response = $response;
  

        return $response->withJSON($func->callMethod($p)['v']);
    });
    $app->patch('/local_language',function(Request $request, Response $response,$args){
        $p = json_decode($request->getBody(), true);
        $p['method'] = 'local_language';
        $func = new MiddlewareV4();
        $func->data_check = ['member_id'=>$p['member_id']];
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }
        $rs = $func->callMethod($p);
        if($rs['c']==0){
            return $response->withJSON($rs['v']);
        }else{
            return $response->withStatus($rs['c'])
            ->withHeader('Content-Type', 'text/html')
            ->write($rs['e']);
        }

    });
    $app->patch('/update_chat_rooms/{member_id:[0-9]+}',function(Request $request, Response $response,$args){
        $p['method'] = 'update_chat_rooms';
        $func = new MiddlewareV4();
        $p['member_id'] = $request->getAttribute('member_id');
        $func->data_check = ['member_id'=>$p['member_id']];
        $func->response = $response;
        $func->preCall($p);
        if(!$func->token['valid']){
            return $func->afterCall(401);
        }

        return $response->withJSON($func->callMethod($p)['v']);

    });

    
    // $app->delete('/logout/{member_id:[0-9]+}',function(Request $request,Response $response,$args){
    //     $p = json_decode($request->getBody(),true);
    //     $p['method'] = 'logout';
    //     $func = new MiddlewareV4();
    //     $p['member_id'] = $request->getAttribute('member_id');
    //     $func->data_check = ['member_id'=>$p['member_id']];
    //     $func->response = $response;
    //     $func->preCall($p);
    //     $func->response = $response;
    //     $func->preCall($p);
    //     if(!$func->token['valid']){
    //         return $func->afterCall(401);
    //     }

    //     $rs = $func->callMethod($p);
    //     if($rs['c']==0){
    //         return $response->withJSON($rs['v']);
    //     }else{
    //         return $response->withStatus($rs['c'])
    //         ->withHeader('Content-Type', 'text/html')
    //         ->write($rs['e']);
    //     }
    //     // return $response->withJSON($func->callMethod($p));
    //     return $response->withJSON($func->callMethod($p));
    // });

    
});

$app->run();
