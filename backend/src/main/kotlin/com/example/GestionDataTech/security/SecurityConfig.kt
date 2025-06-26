package com.example.GestionDataTech.security


import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator
import org.springframework.security.oauth2.core.OAuth2TokenValidator
import org.springframework.security.oauth2.jwt.*
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector
import org.springframework.security.oauth2.server.resource.introspection.SpringOpaqueTokenIntrospector
import org.springframework.security.web.SecurityFilterChain

@Configuration
@EnableWebSecurity
class SecurityConfig {

    @Value("\${auth0.audience}")
    private val audience: String = String()

    @Value("\${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private val issuer: String? = null

    @Value("\${auth0.clientId}")
    private val clientId: String? = null

    @Value("\${auth0.clientSecret}")
    private val clientSecret: String? = null


    @Bean
    fun jwtDecoder(): JwtDecoder {
        val jwtDecoder: NimbusJwtDecoder = JwtDecoders.fromOidcIssuerLocation(issuer) as NimbusJwtDecoder
        val audienceValidator: OAuth2TokenValidator<Jwt> = AudienceValidator(audience)
        val withIssuer: OAuth2TokenValidator<Jwt> = JwtValidators.createDefaultWithIssuer(issuer)
        val withAudience: OAuth2TokenValidator<Jwt> = DelegatingOAuth2TokenValidator(withIssuer, audienceValidator)

        jwtDecoder.setJwtValidator(withAudience)

        return jwtDecoder
    }

    @Bean
    fun opaqueTokenIntrospector(): OpaqueTokenIntrospector {
        return SpringOpaqueTokenIntrospector(
            issuer+"oauth2/introspect", clientId, clientSecret
        )
    }

    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
        http {
            authorizeHttpRequests {
                //authorize("/", permitAll)
                authorize("/helloworld", authenticated)
                authorize(anyRequest, permitAll)
            }
            oauth2ResourceServer {
                jwt {
                    jwtDecoder = jwtDecoder()
                }
                //opaqueToken { }
            }
        }
        return http.build()
    }
}