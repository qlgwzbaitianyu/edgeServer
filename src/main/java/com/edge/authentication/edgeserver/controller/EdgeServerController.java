package com.edge.authentication.edgeserver.controller;

import com.edge.authentication.edgeserver.domain.EdgeServerResponse;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.nio.charset.Charset;

@RestController
public class EdgeServerController {

    @Value("${jwt.secret}")
    private String secretKey;

    @PostMapping(path = "/edge/data")
    public ResponseEntity handleCAV(HttpServletRequest request) {
        return buildEdgeResponse(verifyToken(request));
    }


    private boolean verifyToken(HttpServletRequest request) {
        String token = getToken(request);

        try {
            Jwts.parser().setSigningKey(secretKey.getBytes(Charset.forName("UTF-8"))).parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
            //throw new Exception("Expired or invalid JWT token");
        }
    }

    private String getToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return "";
    }

    private ResponseEntity<EdgeServerResponse> buildEdgeResponse(boolean isVerified) {
        if(isVerified) {
            return new ResponseEntity<>(EdgeServerResponse
                    .builder()
                    .response("Received CAV data")
                    .build(), HttpStatus.OK);
        }
        else {
            return new ResponseEntity<>(EdgeServerResponse.builder()
                    .response("Authentication failed")
                    .build(), HttpStatus.UNAUTHORIZED);
        }
    }

}
