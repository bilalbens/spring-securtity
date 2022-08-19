package com.sid.secservice.sec;

public class JWTUtil {
    public static  final String SECRET="mySecret159753";
    public static  final String AUTH_HEADER="authorization";
    public static  final String PREFIX="Bearer ";

    public static  final String REFRESH_TOKEN_ENDPOINT="/refreshToken";
    public static  final long EXPIRE_ACCESS_TOKEN=2*60*100;
    public static  final long EXPIRE_REFRESH_TOKEN=20*60*100;



}
