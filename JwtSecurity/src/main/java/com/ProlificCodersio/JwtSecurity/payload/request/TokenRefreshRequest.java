package com.ProlificCodersio.JwtSecurity.payload.request;

public class TokenRefreshRequest {

    private String refreshToken;

    public void  setRefreshToken(String refreshToken){this.refreshToken = refreshToken;}
    public String getRefreshToken()
    {
        return refreshToken;
    }

}
