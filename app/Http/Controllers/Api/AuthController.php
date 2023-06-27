<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use App\Models\User;

class AuthController extends Controller
{
    //
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login', 'register']]);
    }

    public function register(Request $request)
    {
        $validator = \Validator::make($request->all(), [
            'name' => ['required'],
            'email' => ['required', 'email', 'unique:users'],
            'password' => ['required']
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => false,
                'message' => $validator->errors()
            ], 400);
        }

        $user = User::create([
            'name' => ucwords($request->name),
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        $token = Auth::login($user);

        return response()->json([
            'status' => true,
            'message' => "Anda berhasil register",
            'user' => $user,
            'authorization' => [
                'token' => $token,
                'type' => 'Bearer'
            ]
        ]);
    }

    public function login(Request $request)
    {
        $validator = \Validator::make($request->all(), [
            'email' => ['required', 'email'],
            'password' => ['required']
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => false,
                'message' => $validator->errors()
            ], 400);
        }

        $loginValue = $request->only('email', 'password');

        $token = Auth::attempt($loginValue);

        if (!$token) {
            return response()->json([
                'status' => false,
                'message' => 'Email atau Password salah'
            ], 400);
        }

        $user = Auth::user();

        return response()->json([
            'status' => true,
            'message' => "Anda berhasil login",
            'user' => $user,
            'authorization' => [
                'token' => $token,
                'type' => 'Bearer'
            ]
        ]);
    }

    public function logout()
    {
        Auth::logout();

        return response()->json([
            'status' => true,
            'message' => "Anda berhasil logout",
        ]);
    }

    public function refreshToken()
    {
        $token = Auth::refresh();
        $user = Auth::user();

        return response()->json([
            'status' => true,
            'message' => "Anda berhasil refresh token",
            'user' => $user,
            'authorization' => [
                'token' => $token,
                'type' => 'Bearer'
            ]
        ]);
    }
}
