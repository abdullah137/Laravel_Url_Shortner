<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Hash;

// User Model Imports
use App\Models\User;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return $request->user();
});

Route::post("/users/signup", function (Request $request) {
    
    // Setting Default headers
    $request->prefers(['application/json']);


    // Setting fields validation
    $fields = $request->validate([
        'username' => 'nullable',
        'email' => 'nullable',
        "password" => 'nullable'
    ]);

    // Checking if each of the fields is field
    if($fields['username'] == "" || $fields['username'] == null 
    || $fields['email'] == "" || $fields['email'] == null
    || $fields['password'] == "" || $fields['password'] == null ) {

        $reponse = [
            "error" => "MISSING_FIELD",
            "status" => false,
            "msg" => "All fields are compulsory"
        ];

        return response($reponse, 401);
    }

    // Check if the email is a valid email address
    if(!filter_var($fields['email'], FILTER_VALIDATE_EMAIL)){
        $reponse = [
            "error" => "INVALID_EMAIL",
            "status" => false,
            "msg" => "Sorry, please enter a valid email address"
        ];

        return response($reponse, 401);
    }

    // Convert letters to lowercase
    $username = Str::lower($fields['username']);
    $email = Str::lower($fields['email']);

    // Check if username or password exits
    $checkUser  = User::whereRaw('username = ? or email = ?', [$username, $email])->count();
    
    if($checkUser > 0)  {
        $reponse = [
            "error" => "USER_EXIST",
            "status" => false,
            "msg" => "Sorry, User already exists"
        ];

        return response($reponse, 401);
    }

    // Creating the user 
    $User = User::create([  
        'username' => $username,
        "email" => $email,
        "password" => bcrypt($fields["password"])
    ]);

    // create user token
    $token = $User->createToken('app')->plainTextToken;

    // Generating the reponse
    $response = [
        "msg" => "USER_CREATED",
        "status" => true,
        "token" => $token,
        "user" => $User, 
    ];

    return response($response, 201);

});

Route::post('/users/signin', function (Request $request) {

     // Setting Default headers
     $request->prefers(['application/json']);


     // Setting fields validation
     $fields = $request->validate([
         'email' => 'nullable',
         "password" => 'nullable'
     ]);
 
     // Checking if each of the fields is field
     if($fields['email'] == "" || $fields['email'] == null
     || $fields['password'] == "" || $fields['password'] == null ) {
 
         $reponse = [
             "error" => "MISSING_FIELD",
             "status" => false,
             "msg" => "All fields are compulsory"
         ];
 
         return response($reponse, 401);
     }

    // Check email
    $user = User::where('email', $fields['email'])->first();

    // Check Password
    if(!$user || !Hash::check($fields['password'], $user->password)) {

        // returning the response
        return response([
            'msg' => 'INVALID_CREDENTIALS',
            'status' => false,
            'message' => "Bad Credentials"
        ], 401);
    }

    $token = $user->createToken('app')->plainTextToken;

    
    $response = [
        "msg" => "SUCCESS",
        'user' => $user,
        'token' => $token
    ];


    return response($response, 201);

}); 

Route::get("/users/logout", function(Request $request) {
    
     // Setting Default headers
     $request->prefers(['application/json']);
     
    // Revoke the token that was used to authenticate the current request...
    $request->user()->tokens()->delete();

        return [
            'message' => 'Logged out'
        ];

});