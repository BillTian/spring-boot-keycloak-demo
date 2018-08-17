package cn.tssit.example.config;

import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.KeycloakConfigResolver;
import org.keycloak.adapters.springboot.KeycloakSpringBootConfigResolver;
import org.keycloak.adapters.springsecurity.KeycloakSecurityComponents;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.keycloak.adapters.springsecurity.client.KeycloakClientRequestFactory;
import org.keycloak.adapters.springsecurity.client.KeycloakRestTemplate;
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;
import org.keycloak.adapters.springsecurity.filter.KeycloakAuthenticationProcessingFilter;
import org.keycloak.adapters.springsecurity.filter.KeycloakPreAuthActionsFilter;
import org.keycloak.representations.AccessToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

import static org.springframework.context.annotation.ScopedProxyMode.TARGET_CLASS;
import static org.springframework.web.context.WebApplicationContext.SCOPE_REQUEST;

@Configuration
@EnableWebSecurity
@ComponentScan(basePackageClasses = KeycloakSecurityComponents.class)
public class SecurityConfig extends KeycloakWebSecurityConfigurerAdapter {

  @Autowired
  public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
    KeycloakAuthenticationProvider keycloakAuthenticationProvider = keycloakAuthenticationProvider();
    SimpleAuthorityMapper grantedAuthorityMapper = new SimpleAuthorityMapper();
    grantedAuthorityMapper.setPrefix("ROLE_");
    grantedAuthorityMapper.setConvertToUpperCase(true);
    keycloakAuthenticationProvider.setGrantedAuthoritiesMapper(grantedAuthorityMapper);
    auth.authenticationProvider(keycloakAuthenticationProvider);
  }

  /**
   * Expose the current {@link AccessToken} on RequestScope.
   *
   * Can be autowired as a Request Scoped Proxy.
   *
   * @return
   */
  @Bean
  @Scope(scopeName = SCOPE_REQUEST, proxyMode = TARGET_CLASS)
  AccessToken getAccessToken() {

    KeycloakSecurityContext context = (KeycloakSecurityContext) RequestContextHolder
      .currentRequestAttributes()
      .getAttribute(KeycloakSecurityContext.class.getName(), RequestAttributes.SCOPE_REQUEST);
    return context.getToken();
  }

  @Autowired
  public KeycloakClientRequestFactory keycloakClientRequestFactory;

  @Bean
  @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
  public KeycloakRestTemplate keycloakRestTemplate() {
    return new KeycloakRestTemplate(keycloakClientRequestFactory);
  }

  // http://www.keycloak.org/docs/3.4/securing_apps/index.html#_spring_security_adapter
  // RegisterSessionAuthenticationStrategy for public or confidential applications
  // and NullAuthenticatedSessionStrategy for bearer-only applications
  @Bean
  @Override
  protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
    return new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl());
  }

  @Bean
  public KeycloakConfigResolver keycloakConfigResolver() {
    return new KeycloakSpringBootConfigResolver();
  }

  // Avoid double Filter bean registration
  @Bean
  public FilterRegistrationBean keycloakAuthenticationProcessingFilterRegistrationBean(KeycloakAuthenticationProcessingFilter filter) {
    FilterRegistrationBean registrationBean = new FilterRegistrationBean(filter);
    registrationBean.setEnabled(false);
    return registrationBean;
  }

  @Bean
  public FilterRegistrationBean keycloakPreAuthActionsFilterRegistrationBean(KeycloakPreAuthActionsFilter filter) {
    FilterRegistrationBean registrationBean = new FilterRegistrationBean(filter);
    registrationBean.setEnabled(false);
    return registrationBean;
  }

  @Override
  public void configure(WebSecurity web) throws Exception {
//    web.ignoring().antMatchers("/css/**", "/js/**",
//      "/images/**", "/webjars/**", "/**/favicon.ico", "/browser/**", "/manage/**");
    web.ignoring().antMatchers("/css/**", "/js/**",
      "/images/**", "/webjars/**", "/**/favicon.ico");
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    super.configure(http);
    http
      .csrf().disable()
      .authorizeRequests()
//      .antMatchers("/manage/**").hasRole("ACTUATOR")
//      .antMatchers("/manage/**").permitAll()
//      .antMatchers("/login*").permitAll()
      .anyRequest().authenticated();

  }
}
