<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

// global variables
$HOSTNAME = "mycompany.sharefile.com";
$USERNAME = "myemail@gmail.com";
$PASSWORD = "mypass";
$CLIENT_ID = "OChwmFTUbOJsbbCu0d21zNU8HHDdMMZz";
$CLIENT_SECRET = "XzLanPKlebwToAjDqr67CfjGcqkabcK6mdVVBeHBhJ6HeWB0";
$FOLDER_ID = "def176f7-77dd-4fc2-111b-11cd9a13fd56";


// error handler with json response
function error($statusCode, $error, $message)
{
    $response = new stdClass();
    $response->statusCode = 300;
    $response->error = "Bad Request";
    $response->message = "No user files provided.";
    return die(json_encode($response));
}


// fetch sharefile access token for given credentials
function authenticate($hostname, $client_id, $client_secret, $username, $password)
{
    // request endpoint
    $uri = "https://$hostname/oauth/token";

    // create post body
    $body_data = array(
        "grant_type" => "password",
        "client_id" => $client_id,
        "client_secret" => $client_secret,
        "username" => $username,
        "password" => $password
    );

    // build post body
    $data = http_build_query($body_data);

    // prepare curl request
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $uri);
    curl_setopt($ch, CURLOPT_FAILONERROR, TRUE);
    curl_setopt($ch, CURLOPT_TIMEOUT, 30);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
    curl_setopt($ch, CURLOPT_VERBOSE, FALSE);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, TRUE);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
    curl_setopt($ch, CURLOPT_POST, TRUE);
    curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type:application/x-www-form-urlencoded'));

    // send curl request
    $auth_response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curl_error = curl_error($ch);

    // close curl request
    curl_close($ch);

    // check if good response
    if ($curl_error) {
        error($http_code, "Authentication Failed", "Unable to fetch Sharefile token!");
    }

    return json_decode($auth_response);
}

// upload file into a given folder id owned by user
function upload_file($token, $folder_id, $local_path, $title, $notes)
{
    // request endpoint
    $uri = "https://$token->subdomain.$token->apicp/sf/v3/Items($folder_id)/Upload?title=$title&details=$notes";

    // request headers
    $headers = array("Authorization: Bearer $token->access_token");

    // (options): prepare curl request
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $uri);
    curl_setopt($ch, CURLOPT_FAILONERROR, TRUE);
    curl_setopt($ch, CURLOPT_TIMEOUT, 300);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
    curl_setopt($ch, CURLOPT_VERBOSE, FALSE);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, TRUE);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

    // (options): send curl request
    $options_response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curl_error = curl_error($ch);

    // (options): check if good response
    if ($curl_error) {
        error($http_code, "Upload Failed", "Unable to fetch Upload config!");
    }

    // (options): success
    $upload_config = json_decode($options_response);

    // (upload): prepare curl request
    $post["File1"] = new CurlFile($local_path);
    curl_setopt($ch, CURLOPT_URL, $upload_config->ChunkUri);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $post);
    curl_setopt($ch, CURLOPT_VERBOSE, FALSE);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HEADER, true);

    // (upload): send curl request
    $upload_response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curl_error = curl_error($ch);

    // close curl request
    curl_close($ch);

    // (upload): check if good response
    if ($curl_error) {
        error($http_code, "Upload Failed", "Unable to send file!");
    }

    return ($http_code == 200) ? TRUE : FALSE;
}

// fetch file details by filename
function find_file($token, $folder_id, $filename)
{
    // request endpoint
    $uri = "https://$token->subdomain.$token->apicp/sf/v3/Items($folder_id)/ByPath?path=$filename";

    // request headers
    $headers = array("Authorization: Bearer $token->access_token");

    // prepare curl request
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $uri);
    curl_setopt($ch, CURLOPT_FAILONERROR, TRUE);
    curl_setopt($ch, CURLOPT_TIMEOUT, 30);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
    curl_setopt($ch, CURLOPT_VERBOSE, FALSE);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, TRUE);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

    // send curl request
    $file_response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curl_error = curl_error($ch);

    // close curl request
    curl_close($ch);

    // check if good response
    if ($curl_error) {
        error($http_code, "Find Failed", "Unable to Find file by name!");
    }

    return json_decode($file_response);
}

// activate file sharing for given file StreamIDs
function share_file($token, $streamIDs)
{

    // request endpoint
    $uri = "https://$token->subdomain.$token->apicp/sf/v3/Shares?notify=false&direct=true";

    // create post body
    $body_data = array(
        "ShareType" => "Send",
        "Title" => "Sample Send Share",
        "Items" => $streamIDs,
        "ExpirationDate" => "2023-07-23",
        "RequireLogin" => false,
        "RequireUserInfo" => false,
        "MaxDownloads" => -1,
        "UsesStreamIDs" => true
    );

    // build post body
    $data = http_build_query($body_data);

    $headers = array("Authorization: Bearer $token->access_token", "Content-Type:application/x-www-form-urlencoded");

    // prepare curl request
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $uri);
    curl_setopt($ch, CURLOPT_FAILONERROR, TRUE);
    curl_setopt($ch, CURLOPT_TIMEOUT, 30);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
    curl_setopt($ch, CURLOPT_VERBOSE, FALSE);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, TRUE);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
    curl_setopt($ch, CURLOPT_POST, TRUE);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

    // send curl request
    $share_response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curl_error = curl_error($ch);

    // close curl request
    curl_close($ch);

    // check if good response
    if ($curl_error) {
        error($http_code, "Share Failed", "Unable to send file!");
    }

    return json_decode($share_response);
}

$_POST = json_decode(file_get_contents('php://input'), true);

// check post parameters
if (!isset($_POST["foobar"])) {
    error(400, "Bad Request", "No user files provided.");
}

// authenticate session
$token = authenticate($HOSTNAME, $CLIENT_ID, $CLIENT_SECRET, $USERNAME, $PASSWORD);

if (!isset($token->access_token)) {
    error(401, "Authentication Failed", "No access_token provided.");
}

// $_POST = json_encode($_POST);

// iterate over user files: download and rename
$user_files = json_decode($_POST["foobar"]);
$file_responses = [];



foreach ($user_files as $key => $user_file) {
    $url = $user_file->url;
    $filename = isset($user_file->filename) ? $user_file->filename : basename($url);

    if (!isset($url)) {
        error(400, "Bad Request", "No URL field provided in user files.");
    }

    file_put_contents("dumps/$filename", fopen($url, 'r'));

    $title = isset($user_file->title) ? $user_file->title : 'Default Title';
    $notes = isset($user_file->notes) ? $user_file->notes : 'Default Notes';

    $upload_response = upload_file($token, $FOLDER_ID, "dumps/$filename", $title, $notes);
    $file_response = find_file($token, $FOLDER_ID, $filename);

    // push file details
    array_push($file_responses, $file_response);
}

header('Content-type:application/json;charset=utf-8');

echo json_encode($file_responses);