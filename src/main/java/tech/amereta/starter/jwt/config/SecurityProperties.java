package tech.amereta.starter.jwt.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import tech.amereta.starter.jwt.utils.StringUtils;

@Component
@ConfigurationProperties(prefix = "amereta.security", ignoreUnknownFields = false)
public class SecurityProperties {

    private String secretKey = StringUtils.randomBase64(256);
    private Long simpleTokenValidity = 1800L;
    private Long rememberMeTokenValidity = 2592000L;

    public String getSecretKey() {
        return secretKey;
    }

    public void setSecretKey(String secretKey) {
        this.secretKey = secretKey;
    }

    public Long getSimpleTokenValidity() {
        return simpleTokenValidity;
    }

    public void setSimpleTokenValidity(Long simpleTokenValidity) {
        this.simpleTokenValidity = simpleTokenValidity;
    }

    public Long getRememberMeTokenValidity() {
        return rememberMeTokenValidity;
    }

    public void setRememberMeTokenValidity(Long rememberMeTokenValidity) {
        this.rememberMeTokenValidity = rememberMeTokenValidity;
    }
}
