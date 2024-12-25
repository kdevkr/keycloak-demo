package kr.kdev.backoffice;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;

@Slf4j
@ControllerAdvice
@Controller
public class IndexController {

    @ModelAttribute("principal")
    public OidcUser principal(@AuthenticationPrincipal OidcUser principal) {
        return principal; // NOTE: Use principal in Thymeleaf view.
    }

    @GetMapping("/")
    public String index(@AuthenticationPrincipal OidcUser principal) {
        if (principal != null) {
            log.info("username: {}, email: {}, authorities: {}",
                    principal.getName(), principal.getEmail(), principal.getAuthorities());
        }
        return "index";
    }
}
