# Aplicativo seguro de registro e login do Spring Security 

## Introdução
<p text-align="justify">
Esse aplicativo aborda a implementação do registro de usuário com User e Admin implementando a interface AuthenticationSuccessHandler e possui método de autoridade para distribuir permissão entre usuários, funcionalidade de login e criptografia de senha usando Spring Security.
</p>

## Spring Security

<p text-align="justify">
O Spring Security é um framework de segurança poderoso e altamente configurável para aplicativos Java. Ele fornece recursos de autenticação e autorização robustos para proteger seus aplicativos web. 

O Spring Security é uma parte integrante do ecossistema Spring e se concentra em quatro áreas principais:
</p>

1. **Autenticação**: 
    - `Definição:` A autenticação é o processo de verificar a identidade de um usuário, ou seja, confirmar se uma pessoa ou entidade é realmente quem alega ser.
    - `Objetivo:` O objetivo da autenticação é garantir que apenas pessoas autorizadas tenham acesso aos recursos de um sistema.
    - `Exemplo:` Digitar um nome de usuário e senha para fazer login em uma conta de usuário é um processo de autenticação comum.

2. **Autorização**: Determinar o que um usuário autenticado tem permissão para fazer.
    - `Definição:` A autorização é o processo de determinar o que um usuário autenticado tem permissão para fazer dentro de um sistema. Ela lida com a concessão ou negação de acesso a recursos específicos com base nas permissões do usuário.
    - `Objetivo:` O objetivo da autorização é garantir que os usuários só tenham acesso aos recursos ou funcionalidades para os quais têm permissão.
    - `Exemplo:` Após fazer login, um usuário pode ser autorizado a acessar recursos específicos com base em seu papel ou função, como visualizar, editar ou excluir determinados dados.

3. **Proteção contra Ameaças**: Defesa contra vulnerabilidades de segurança comuns, como ataques de segurança da web.

4. **Suporte para Integração**: Integração com outros frameworks e soluções de segurança.

---
<p text-align="justify">
Em resumo, a autenticação trata da identificação e verificação da identidade de um usuário, enquanto a autorização lida com a determinação das permissões de um usuário após a autenticação. Ambos os conceitos são fundamentais para a segurança de sistemas, especialmente em aplicativos e sistemas que exigem controle de acesso preciso e proteção de informações sensíveis. Em muitos cenários, a autenticação é o primeiro passo, seguido pela autorização para controlar o acesso do usuário aos recursos do sistema.
</p>

---

## Roles (Papéis)

<p text-align="justify">
Os papéis (ou "roles") são definidos na autorização. Já na autenticação, o objetivo é verificar a identidade do usuário, normalmente usando um mecanismo como um nome de usuário e senha. A autorização, por outro lado, lida com a atribuição de permissões específicas ao usuário após a autenticação.

Quando um usuário é autenticado com sucesso, seu identificador (geralmente o nome de usuário) é usado para determinar quais papéis ou funções esse usuário possui. Esses papéis ou funções são definidos no contexto da autorização e determinam o que o usuário está autorizado a fazer em um sistema.

Por exemplo, após a autenticação bem-sucedida de um usuário, o sistema verifica quais papéis (ou funções) o usuário possui e, em seguida, concede permissões com base nesses papéis. Por exemplo:
</p>

- Um usuário com o papel "ROLE_USER" pode ter permissão apenas para visualizar informações do sistema.
- Um usuário com o papel "ROLE_ADMIN" pode ter permissão para fazer modificações e administrar o sistema.

<p text-align="justify">
Esses papéis (ou roles) são definidos no contexto da autorização e são usados para controlar o acesso do usuário a recursos específicos no sistema. Portanto, a autenticação verifica a identidade do usuário, enquanto a autorização determina o que o usuário pode fazer após a autenticação com base em seus papéis ou funções.
</p>


## Classe de Modelo "User"

A classe de modelo chamada `User` em um aplicativo Spring Security é mapeada para uma tabela no banco de dados por meio de anotações JPA (Java Persistence API). Ela é usada para representar os dados do usuário no sistema.

```java
package com.springsecurity.apitelalogin.model;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;

@Entity
@Table(name = "users", uniqueConstraints = @UniqueConstraint(columnNames = "email"))
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String email;
    private String password;
    private String role;
    private String fullname;

    public User() {
        super();
    }

    public User(String email, String password, String role, String fullname) {
        this.email = email;
        this.password = password;
        this.role = role;
        this.fullname = fullname;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public String getFullname() {
        return fullname;
    }

    public void setFullname(String fullname) {
        this.fullname = fullname;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((id == null) ? 0 : id.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        User other = (User) obj;
        if (id == null) {
            if (other.id != null)
                return false;
        } else if (!id.equals(other.id))
            return false;
        return true;
    }

}
```

### Anotações de Classe

- `@Entity`: Indica que esta classe é uma entidade JPA, ou seja, será mapeada para uma tabela no banco de dados.

- `@Table`: Define o nome da tabela no banco de dados e a restrição de unicidade no campo "email".

- `@UniqueConstraint`: Define uma restrição de unicidade no campo "email", garantindo que não haja duplicatas de e-mails na tabela.

### Atributos da Classe

- `id`: É a chave primária da tabela e é gerada automaticamente usando a estratégia `GenerationType.IDENTITY`.

- `email`: Representa o endereço de e-mail do usuário.

- `password`: Representa a senha do usuário.

- `role`: Representa a função ou papel do usuário no sistema.

- `fullname`: Representa o nome completo do usuário.

### Construtores

- `User()`: Construtor padrão sem argumentos.

- `User(String email, String password, String role, String fullname)`: Construtor que aceita os detalhes do usuário como argumentos e os atribui aos campos correspondentes.

### Métodos Getters e Setters

Existem métodos getters e setters para acessar e modificar os atributos da classe, como `getId()`, `getEmail()`, `getPassword()`, `getRole()`, `getFullname()`, `setId()`, `setEmail()`, `setPassword()`, `setRole()`, `setFullname()`, entre outros.

### Métodos `hashCode` e `equals`

Esses métodos são substituídos para permitir comparações adequadas entre objetos `User`. O método `hashCode` é usado para gerar um código hash único com base no `id` do usuário. O método `equals` compara objetos `User` com base em seus `id` para verificar se são iguais.

Esta classe é um componente essencial para representar usuários no sistema e é frequentemente usada em conjunto com o Spring Security para autenticação e autorização de usuários.


## Interface Repository "UserRepository"

A interface de repositório chamada `UserRepository` em um aplicativo Spring Security estende o `JpaRepository` do Spring Data, o que a torna responsável por operações de acesso a dados relacionadas à entidade `User`.

```java
package com.springsecurity.apitelalogin.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.springsecurity.apitelalogin.model.User;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    User findByEmail(String email);
}
```

### Anotações de Interface

- `@Repository`: Indica que esta interface é um componente de repositório Spring, responsável por gerenciar o acesso aos dados da entidade `User`. É uma anotação do Spring Framework que permite que a classe seja detectada automaticamente como um componente gerenciado pelo Spring.

### Extensão de JpaRepository

- `JpaRepository<User, Long>`: Esta interface estende a interface `JpaRepository` do Spring Data. A primeira parâmetro, `User`, especifica a entidade à qual esta interface está associada (no caso, a classe `User`). O segundo parâmetro, `Long`, representa o tipo da chave primária da entidade.

### Métodos Personalizados

- `User findByEmail(String email)`: Este é um método personalizado adicionado ao repositório. Ele permite buscar um usuário com base em seu endereço de e-mail. O Spring Data JPA gera a consulta SQL apropriada para essa operação com base no nome do método.

Esta interface é uma parte essencial do aplicativo, pois fornece um mecanismo para acessar e manipular dados de usuário no banco de dados. Ela é frequentemente usada em conjunto com outras classes e componentes do Spring Data JPA para criar operações de CRUD (Create, Read, Update, Delete) para a entidade `User`.

## Classe DTO "UserDto"

A classe de Transferência de Dados (DTO, Data Transfer Object) chamada `UserDto` em um aplicativo Spring Security são usados para transportar dados entre componentes, muitas vezes entre a camada de apresentação e a camada de serviços.

```java
package com.springsecurity.apitelalogin.dto;

public class UserDto {

    private String email;
    private String password;
    private String role;
    private String fullname;

    public UserDto(String email, String password, String role, String fullname) {
        this.email = email;
        this.password = password;
        this.role = role;
        this.fullname = fullname;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public String getFullname() {
        return fullname;
    }

    public void setFullname(String fullname) {
        this.fullname = fullname;
    }

}
```

### Atributos da Classe

- `email`: Representa o endereço de e-mail do usuário.

- `password`: Representa a senha do usuário.

- `role`: Representa a função ou papel do usuário no sistema.

- `fullname`: Representa o nome completo do usuário.

### Construtor

- `UserDto(String email, String password, String role, String fullname)`: Construtor que aceita os detalhes do usuário como argumentos e os atribui aos campos correspondentes. Este construtor é usado para criar instâncias da classe `UserDto` com informações do usuário.

### Métodos Getters e Setters

Existem métodos getters e setters para acessar e modificar os atributos da classe, como `getEmail()`, `getPassword()`, `getRole()`, `getFullname()`, `setEmail()`, `setPassword()`, `setRole()`, `setFullname()`, entre outros.

### Utilização

A classe `UserDto` é frequentemente usada para representar dados de usuário durante a entrada de informações, transporte de dados entre camadas do aplicativo e processamento de solicitações. Ela serve como um modelo de dados leve que contém apenas os campos necessários para operações específicas, como registro ou autenticação.

## Interface "UserService"

A interface chamada `UserService` em um aplicativo Spring Security define um contrato para operações de serviço relacionadas aos usuários, especificamente a criação de usuários com base em dados fornecidos por objetos `UserDto`.

```java
package com.springsecurity.apitelalogin.service;

import com.springsecurity.apitelalogin.dto.UserDto;
import com.springsecurity.apitelalogin.model.User;

public interface UserService {
    
    User save(UserDto userDto);
}
```

### Métodos da Interface

- `User save(UserDto userDto)`: Este método da interface `UserService` é responsável por salvar um novo usuário no sistema com base nos detalhes fornecidos por um objeto `UserDto`. Ele aceita um objeto `UserDto` contendo as informações do usuário a ser criado e retorna um objeto `User` que representa o usuário recém-criado no sistema.

### Utilização

A interface `UserService` desempenha um papel importante na lógica de negócios do aplicativo, permitindo a criação de usuários com base em dados de entrada. Essa interface define um contrato que pode ser implementado por classes de serviço concretas que lidam com a lógica de criação de usuário.

A implementação real deste método envolverá a criação de um objeto `User` com base nas informações fornecidas no `UserDto`, a codificação segura da senha e a interação com o repositório de dados (usando o `UserRepository`).

## Classe de Serviço "UserServiceImpl"

A classe de serviço chamada `UserServiceImpl` em um aplicativo Spring Security é uma implementação da interface `UserService` e é responsável pela criação de usuários no sistema com base nos dados fornecidos por objetos `UserDto`.

```java
package com.springsecurity.apitelalogin.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.springsecurity.apitelalogin.dto.UserDto;
import com.springsecurity.apitelalogin.model.User;
import com.springsecurity.apitelalogin.repositories.UserRepository;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private UserRepository userRepository;

    // Criptografar senhas e verificar senhas fornecidas durante o processo de autenticação
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public User save(UserDto userDto) {

        User user = new User(userDto.getEmail(), passwordEncoder.encode(userDto.getPassword()), userDto.getRole(), userDto.getFullname());
        return userRepository.save(user);
    }

}
```

### Anotações de Classe

- `@Service`: Indica que esta classe é um componente de serviço Spring, ou seja, ela contém a lógica de negócios para operações relacionadas aos usuários. É uma anotação do Spring Framework que permite que a classe seja detectada automaticamente como um componente gerenciado pelo Spring.

### Atributos da Classe

- `userRepository`: É uma instância da classe `UserRepository` injetada usando a anotação `@Autowired`. Essa instância permite a interação com o repositório de dados para salvar os objetos `User`.

- `passwordEncoder`: É uma instância de `PasswordEncoder` injetada usando a anotação `@Autowired`. Essa instância é usada para criptografar senhas e verificar senhas fornecidas durante o processo de autenticação.

### Métodos

- `User save(UserDto userDto)`: Este método da classe `UserServiceImpl` implementa o contrato da interface `UserService`. Ele recebe um objeto `UserDto` contendo os detalhes do usuário a ser criado. O método cria um novo objeto `User`, criptografa a senha fornecida usando o `passwordEncoder` e, em seguida, salva o novo usuário no banco de dados usando o `userRepository`. O usuário recém-criado é retornado como resultado.

### Utilização

A classe `UserServiceImpl` é essencial para a criação de usuários no sistema. Ela lida com a lógica de negócios associada à criação de usuários, garantindo que as senhas sejam armazenadas de forma segura após a criptografia. A injeção do `UserRepository` permite que a classe interaja com o banco de dados para salvar os usuários criados.

Esta classe é tipicamente utilizada em conjunto com o controlador que processa solicitações de registro de novos usuários.


## Classe "CustomUserDetail"

A Classe `CustomUserDetail` em um aplicativo Spring Security implementa a interface `UserDetails` e é usada para encapsular informações de usuário e credenciais, permitindo a autenticação e autorização no sistema.

```java
package com.springsecurity.apitelalogin.service;

import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.springsecurity.apitelalogin.model.User;

public class CustomUserDetail implements UserDetails {

    private User user;

    public CustomUserDetail(User user) {
        this.user = user;
    }

    // Métodos já definidos para obter informações sobre um usuário e suas credenciais.
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(() -> user.getRole());
    }

    // Método criado para capturar o fullname
    public String getFullname() {
        return user.getFullname();
    }

    // Métodos já definidos para obter informações sobre um usuário e suas credenciais.
    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getEmail();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

}
```

### Construtor

- `CustomUserDetail(User user)`: Este é o construtor da classe `CustomUserDetail`. Ele aceita um objeto `User` como argumento e o associa à instância `CustomUserDetail`. Isso permite que a classe encapsule as informações de usuário associadas a esse objeto.

### Métodos

#### `getAuthorities()`

- `Collection<? extends GrantedAuthority> getAuthorities()`: Este método é implementado a partir da interface `UserDetails` e é usado para obter as autorizações associadas ao usuário. Neste caso, o método retorna uma lista contendo a função ou papel do usuário obtida do objeto `User`.

#### `getFullname()`

- `String getFullname()`: Este é um método personalizado adicionado à classe `CustomUserDetail` para obter o nome completo do usuário associado a essa instância.

### Outros Métodos da Interface `UserDetails`

A classe `CustomUserDetail` também implementa outros métodos da interface `UserDetails`, como:
  
   1. `getPassword()`: Retorna a senha do usuário. Normalmente, a senha é armazenada com segurança e criptografada.

   2. `getUsername()`: Retorna o nome de usuário do usuário.

   3. `isAccountNonExpired()`: Indica se a conta do usuário não está expirada.

   4. `isAccountNonLocked()`: Indica se a conta do usuário não está bloqueada.

   5. `isCredentialsNonExpired()`: Indica se as credenciais do usuário (normalmente, a senha) não estão expiradas.

   6. `isEnabled()`: Indica se a conta do usuário está habilitada ou desabilitada.

Esses métodos fornecem informações sobre as credenciais do usuário e seu status de conta.

### Utilização

A classe `CustomUserDetail` é usada para representar informações de usuário que são relevantes para o processo de autenticação e autorização. Ela encapsula informações como nome de usuário, senha, autorizações e outros detalhes relevantes. Essa classe geralmente é utilizada em conjunto com o Spring Security para autenticar usuários e determinar as autorizações com base em seu papel.

A personalização da classe permite adicionar informações adicionais, como o nome completo do usuário, para serem acessadas facilmente em outras partes do aplicativo.

## Classe de Serviço "CustomUserDetailService"

A classe de serviço chamada `CustomUserDetailService` em um aplicativo Spring Security implementa a interface `UserDetailsService` e é responsável por carregar os detalhes do usuário com base no nome de usuário (no caso, o endereço de e-mail) durante o processo de autenticação.

```java
package com.springsecurity.apitelalogin.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.springsecurity.apitelalogin.model.User;
import com.springsecurity.apitelalogin.repositories.UserRepository;

@Service
public class CustomUserDetailService implements UserDetailsService{

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        
        User user = userRepository.findByEmail(username);

        if(user == null){
            throw new UsernameNotFoundException("user not found");
        }

        return new CustomUserDetail(user);
    }
    
}
```

### Anotações de Classe

- `@Service`: Indica que esta classe é um componente de serviço Spring, responsável por fornecer a funcionalidade de carregamento de detalhes do usuário durante a autenticação. É uma anotação do Spring Framework que permite que a classe seja detectada automaticamente como um componente gerenciado pelo Spring.

### Atributos da Classe

- `userRepository`: É uma instância da classe `UserRepository` injetada usando a anotação `@Autowired`. Essa instância permite a interação com o repositório de dados para recuperar detalhes do usuário com base no nome de usuário (endereço de e-mail).

### Métodos

#### `loadUserByUsername()`

- `UserDetails loadUserByUsername(String username) throws UsernameNotFoundException`: Este método é implementado a partir da interface `UserDetailsService` e é usado para carregar os detalhes do usuário com base no nome de usuário fornecido (geralmente, o endereço de e-mail). O método faz uma consulta ao repositório de dados para recuperar o usuário com o nome de usuário especificado. Se o usuário não for encontrado, uma exceção `UsernameNotFoundException` é lançada. Caso contrário, os detalhes do usuário são encapsulados em um objeto `CustomUserDetail` (ou qualquer outra implementação de `UserDetails`) e retornados.

### Utilização

A classe `CustomUserDetailService` é usada como parte do processo de autenticação do Spring Security. Quando um usuário tenta fazer login, o método `loadUserByUsername` é chamado para recuperar os detalhes do usuário com base no nome de usuário fornecido. Isso é fundamental para autenticar o usuário e determinar suas autorizações com base em suas credenciais.

## Classe de Configuração "SecurityConfig"

A classe de configuração chamada `SecurityConfig` em um aplicativo Spring Security é responsável por configurar a segurança do aplicativo, incluindo autenticação, autorização e outras configurações relacionadas à segurança.

```java
package com.springsecurity.apitelalogin.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.springsecurity.apitelalogin.service.CustomSuccessHandler;
import com.springsecurity.apitelalogin.service.CustomUserDetailService;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private CustomUserDetailService customUserDetailService;

    @Autowired
    private CustomSuccessHandler customSuccessHandler;

    @Bean
    public static PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.csrf(c -> c.disable())
                .authorizeHttpRequests(request -> request.requestMatchers("/admin-page").hasAuthority("ADMIN")
                        .requestMatchers("/user-page").hasAnyAuthority("USER")
                        .requestMatchers("/registration", "/css/**").permitAll()
                        .anyRequest()
                        .authenticated())
                .formLogin(form -> form.loginPage("/login")
                        .loginProcessingUrl("/login")
                        .successHandler(customSuccessHandler).permitAll())
                .logout(form -> form.invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                        .logoutSuccessUrl("/login?logout").permitAll());

        return httpSecurity.build();
    }

    @Autowired
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(customUserDetailService).passwordEncoder(passwordEncoder());
    }
}
```

### Anotações de Classe

- `@Configuration`: Indica que esta classe é uma classe de configuração do Spring. Ela é usada para definir configurações específicas do aplicativo.

- `@EnableWebSecurity`: Indica que esta classe é uma classe de configuração de segurança da web do Spring. Ela permite que o Spring Security seja ativado no aplicativo.

### Atributos da Classe

- `customUserDetailService`: É uma instância da classe `CustomUserDetailService` injetada usando a anotação `@Autowired`. Essa instância é usada para carregar detalhes do usuário durante o processo de autenticação.

- `customSuccessHandler`: É uma instância da classe `CustomSuccessHandler` injetada usando a anotação `@Autowired`. Essa instância lida com o redirecionamento após o sucesso do login.

### Métodos

#### `passwordEncoder()`

- `@Bean`: Indica que este método é um bean gerenciado pelo Spring. Ele fornece uma instância de `PasswordEncoder`, neste caso, `BCryptPasswordEncoder`, que é usada para codificar senhas de forma segura.

#### `securityFilterChain()`

- `@Bean`: Indica que este método configura e retorna um `SecurityFilterChain`, que é uma cadeia de filtros de segurança. A configuração define regras de segurança para URLs específicas e configurações relacionadas ao login e logout.

#### `configure(AuthenticationManagerBuilder auth)`

- `@Autowired`: Indica que este método é injetado com uma instância de `AuthenticationManagerBuilder`. Ele configura o gerenciamento de autenticação, definindo o serviço de detalhes do usuário e o codificador de senhas.

### Utilização

A classe `SecurityConfig` é uma parte fundamental de um aplicativo Spring Security, onde são definidas configurações de segurança. Ela configura como as solicitações HTTP são protegidas, quem pode acessar recursos específicos e como a autenticação e autorização são gerenciadas.

Esta classe também define o redirecionamento após o login bem-sucedido usando o `customSuccessHandler` e configura o `BCryptPasswordEncoder` para garantir que as senhas sejam armazenadas com segurança no sistema.

## Classe de Serviço "CustomSuccessHandler"

A classe de serviço chamada `CustomSuccessHandler` em um aplicativo Spring Security implementa a interface `AuthenticationSuccessHandler` e é responsável por lidar com o redirecionamento após o sucesso da autenticação do usuário.

```java
package com.springsecurity.apitelalogin.service;

import java.io.IOException;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Service;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Service
public class CustomSuccessHandler implements AuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {

        // var é uma Optional
        var authourities = authentication.getAuthorities();
        var roles = authourities.stream().map(r -> r.getAuthority()).findFirst();

        if (roles.orElse("").equals("ADMIN")) {
            response.sendRedirect("/admin-page");
        } else if (roles.orElse("").equals("USER")) {
            response.sendRedirect("/user-page");
        } else {
            response.sendRedirect("/error");
        }
    }

}
```

### Anotações de Classe

- `@Service`: Indica que esta classe é um componente de serviço Spring. Ela é responsável por fornecer funcionalidades relacionadas ao sucesso da autenticação e redirecionamento após o login.

### Métodos

#### `onAuthenticationSuccess()`

- `void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException`: Este é o método principal da classe, implementado a partir da interface `AuthenticationSuccessHandler`. Ele é invocado quando a autenticação do usuário é bem-sucedida. O método recebe os objetos `HttpServletRequest`, `HttpServletResponse` e `Authentication` como argumentos.

  - `HttpServletRequest request`: Representa a solicitação HTTP enviada pelo cliente.

  - `HttpServletResponse response`: Representa a resposta HTTP que será enviada de volta ao cliente.

  - `Authentication authentication`: Contém informações sobre a autenticação do usuário, incluindo suas autorizações.

- `var authourities`: É uma variável definida como um objeto `Optional`. Ela obtém as autorizações (papéis) do usuário autenticado. Essas autorizações são extraídas a partir do objeto `Authentication`.

- `var roles`: É uma variável que obtém os papéis (autorizações) do usuário autenticado a partir do objeto `authourities` usando uma operação de mapeamento.

- O método verifica o primeiro papel encontrado usando `findFirst()` e, com base no papel do usuário, redireciona o usuário para páginas específicas. Se o papel for "ADMIN", o redirecionamento é feito para "/admin-page". Se o papel for "USER", o redirecionamento é feito para "/user-page". Caso contrário, se nenhum papel for encontrado ou não corresponder a nenhum dos casos, o usuário é redirecionado para "/error".

## Utilização

A classe `CustomSuccessHandler` é usada para definir a lógica de redirecionamento após o login bem-sucedido. Ela permite direcionar os usuários para páginas específicas com base em seus papéis de autorização. Isso é útil para controlar o fluxo de navegação no aplicativo após o login.

Essa classe é geralmente usada em conjunto com a configuração de segurança para definir como o sucesso da autenticação deve ser tratado, especificando o `customSuccessHandler` como o manipulador de sucesso.

## Classe de Controlador "UserController"

A classe de controlador chamada `UserController` em um aplicativo Spring Security é responsável por gerenciar as solicitações relacionadas à autenticação e autorização de usuários, incluindo o registro, login e páginas específicas para usuários autenticados.

```java
package com.springsecurity.apitelalogin.controller;

import java.security.Principal;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

import com.springsecurity.apitelalogin.dto.UserDto;
import com.springsecurity.apitelalogin.service.UserService;

@Controller
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private UserDetailsService userDetailsService;

    // http://localhost:8080/registration
    @GetMapping("/registration")
    public String getRegistrationPage(@ModelAttribute("user") UserDto userDto) {
        return "register";
    }

    // http://localhost:8080/registration
    @PostMapping("/registration")
    public String saveUser(@ModelAttribute("user") UserDto userDto, Model model) {

        userService.save(userDto);
        model.addAttribute("message", "Registered Successfuly");

        return "register";
    }

    // http://localhost:8080/login
    @GetMapping("/login")
    public String login(){
        return "login";
    }

    // http://localhost:8080/user-page
    @GetMapping("/user-page")
    public String userPage(Model model, Principal principal){
        UserDetails userDetails = userDetailsService.loadUserByUsername(principal.getName());
        model.addAttribute("user", userDetails);
        return "user";
    }

    // http://localhost:8080/admin-page
    @GetMapping("/admin-page")
    public String adminPage(Model model, Principal principal){
        UserDetails userDetails = userDetailsService.loadUserByUsername(principal.getName());
        model.addAttribute("user", userDetails);
        return "admin";
    }

}
```

### Anotações de Classe

- `@Controller`: Indica que esta classe é um controlador Spring. Ela é responsável por lidar com as solicitações HTTP e definir o comportamento correspondente.

### Atributos da Classe

- `userService`: É uma instância da classe `UserService` injetada usando a anotação `@Autowired`. Essa instância é usada para lidar com as operações relacionadas ao usuário, como o registro de um novo usuário.

- `userDetailsService`: É uma instância da classe `UserDetailsService` injetada usando a anotação `@Autowired`. Essa instância é usada para carregar detalhes do usuário durante o processo de autenticação.

### Métodos

#### `getRegistrationPage()`

- `@GetMapping("/registration")`: Este método é mapeado para a URL "/registration" e lida com solicitações GET para a página de registro. Ele retorna a página "register", que é usada para registrar um novo usuário.

#### `saveUser()`

- `@PostMapping("/registration")`: Este método é mapeado para a URL "/registration" e lida com solicitações POST para salvar os dados de registro de um novo usuário. Ele recebe os dados do usuário no objeto `UserDto`, realiza o registro usando o serviço `userService` e retorna a página "register". Além disso, ele adiciona uma mensagem de sucesso ("Registered Successfuly") ao modelo.

#### `login()`

- `@GetMapping("/login")`: Este método é mapeado para a URL "/login" e lida com solicitações GET para a página de login. Ele retorna a página "login", que é usada para a autenticação do usuário.

#### `userPage()`

- `@GetMapping("/user-page")`: Este método é mapeado para a URL "/user-page" e lida com solicitações GET para a página do usuário. Ele obtém os detalhes do usuário autenticado usando o serviço `userDetailsService` e os adiciona ao modelo. Em seguida, retorna a página "user", que pode exibir informações específicas do usuário.

#### `adminPage()`

- `@GetMapping("/admin-page")`: Este método é mapeado para a URL "/admin-page" e lida com solicitações GET para a página do administrador. Ele segue a mesma lógica que o método `userPage`, mas é usado para exibir informações específicas do administrador.

### Utilização

A classe `UserController` é fundamental para a gestão de páginas e ações relacionadas à autenticação e autorização de usuários. Ela lida com o registro de novos usuários, login e apresentação de páginas específicas com base nas autorizações do usuário. Além disso, a classe lida com o redirecionamento após o registro e o login bem-sucedidos.

Essa classe é geralmente usada em conjunto com as configurações de segurança e a lógica de serviço para criar um fluxo de autenticação e autorização eficaz em um aplicativo Spring Security.

## Página de Formulário de Registro

O código HTML representa uma página de formulário de registro em um aplicativo da web. A página é usada para permitir que os usuários se registrem fornecendo suas informações pessoais. Este código faz uso da linguagem de modelo Thymeleaf para renderização dinâmica de dados.

```html
<!DOCTYPE html>
<html lang="en" xmlns:th="http://www.thymeleaf.org">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Registration Form</title>
    <link rel="stylesheet" th:href="@{../css/styles.css}">
  </head>
  <body>
    <div class="container">

      <div class="message" th:if="${message != null}">
        [[${message}]]
      </div>

      <h2>Registration Form</h2>
      <form th:action="@{/registration}" method="post" role="form" th:object="${user}">

        <div class="form-group">
            <label for="fullname">Fullname:</label>
            <input th:field="*{fullname}" type="text" id="fullname" name="fullname" placeholder="Enter your fullname" required />
        </div>

        <div class="form-group">
          <label for="email">Email:</label>
          <input th:field="*{email}" type="email" id="email" name="email" placeholder="Enter your email" required />
        </div>

        <div class="form-group">
          <label for="password">Password:</label>
          <input th:field="*{password}" type="password" id="password" name="password" placeholder="Enter your password" required />
        </div>
        <input type="submit" value="Register" />
      </form>
    </div>

  </body>
</html>
```

**Imagem da Página de Formulário de Registro**

 A página de formulário de registro é acessada através do seguinte link: `http://localhost:8080/registration`. 

<p align="center">
  <img src=".\src\main\resources\static\img\Tela_registro.png" alt="Página de Formulário de Registro" width=800/>
</p>

### Corpo da Página

  - `<div class="container">`: Um contêiner principal para o conteúdo da página.

    - `<div class="message" th:if="${message != null}">`: Uma seção de mensagem condicional. Se a variável `${message}` estiver definida (não nula), a mensagem será exibida. Isso é útil para mostrar mensagens de sucesso após o registro.

      - `[[${message}]]`: A mensagem em si, que é renderizada dinamicamente usando a sintaxe do Thymeleaf.

    - `<h2>Registration Form</h2>`: Título da página que descreve o propósito do formulário.

    - `<form th:action="@{/registration}" method="post" role="form" th:object="${user}">`: Um formulário HTML com atributos Thymeleaf que definem o URL de ação, o método HTTP (POST), o papel do formulário e o objeto de modelo a ser associado.

      - Campos de Entrada do Formulário:

        - Três campos de entrada de formulário para "Fullname," "Email," e "Password." Cada campo possui um rótulo, um tipo (text, email ou password) e a capacidade de receber entradas obrigatórias.

        - Os atributos `th:field` e `*{}` são usados para vincular os campos de entrada ao modelo de dados `${user}` usando Thymeleaf.

      - `<input type="submit" value="Register" />`: Um botão de envio para submeter o formulário.

### Utilização

Este código HTML representa uma página de registro em um aplicativo web. Ela permite aos usuários inserirem suas informações pessoais, como nome, email e senha, e se registrarem no sistema. O Thymeleaf é usado para tornar o código dinâmico, permitindo a exibição condicional de mensagens e o preenchimento de campos com dados do modelo.

## Página de Formulário de Login

O código HTML representa uma página de formulário de login em um aplicativo da web. A página é usada para permitir que os usuários façam login fornecendo suas credenciais. Este código faz uso da linguagem de modelo Thymeleaf para renderização dinâmica de dados.

```html
<!DOCTYPE html>
<html lang="en" xmlns:th="http://www.thymeleaf.org">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Login Form</title>
    <link rel="stylesheet" th:href="@{../css/styles.css}">
  </head>
  <body>
    <div class="container">

      <div class="message" th:if="${param.error}">
        Invalid Username or Password
      </div>

      <div class="message" th:if="${param.logout}">
        Logout Successfuly
      </div>

      <h2>Admin and User Login Page</h2>
      <form th:action="@{/login}" method="post">

        <div class="form-group">
          <label for="username">Email:</label>
          <input type="email" id="username" name="username" placeholder="Enter your email" required />
        </div>

        <div class="form-group">
          <label for="password">Password:</label>
          <input type="password" id="password" name="password" placeholder="Enter your password" required />
        </div>
        <input type="submit" value="Register" />
      </form>
    </div>

  </body>
</html>
```

**Imagem da Página de Formulário de Login**

 A página de formulário de login é acessada através do seguinte link: `http://localhost:8080/login`. 

<p align="center">
  <img src=".\src\main\resources\static\img\Tela_login.png" alt="Página de Formulário de Login" width=800/>
</p>


### Corpo da Página

  - `<div class="container">`: Um contêiner principal para o conteúdo da página.

    - `<div class="message" th:if="${param.error}">`: Uma seção de mensagem condicional que é exibida se o parâmetro `error` estiver presente na URL. Isso geralmente indica uma tentativa de login mal-sucedida.

      - "Invalid Username or Password": A mensagem de erro que é exibida se o parâmetro `error` estiver presente.

    - `<div class="message" th:if="${param.logout}">`: Uma seção de mensagem condicional que é exibida se o parâmetro `logout` estiver presente na URL. Isso indica que o logout foi realizado com sucesso.

      - "Logout Successfuly": A mensagem exibida após um logout bem-sucedido.

    - `<h2>Admin and User Login Page</h2>`: Título da página que descreve o propósito do formulário.

    - `<form th:action="@{/login}" method="post">`: Um formulário HTML com atributos Thymeleaf que definem o URL de ação (onde os dados do formulário serão enviados) e o método HTTP (POST).

      - Campos de Entrada do Formulário:

        - Dois campos de entrada de formulário para "Email" (usando tipo "email") e "Password" (usando tipo "password"). Cada campo possui um rótulo e a capacidade de receber entradas obrigatórias.

      - `<input type="submit" value="Register" />`: Um botão de envio para submeter o formulário.

### Utilização

Este código HTML representa uma página de login em um aplicativo web. Ela permite que os usuários insiram suas credenciais (email e senha) para acessar o sistema. O Thymeleaf é usado para tornar o código dinâmico, permitindo a exibição condicional de mensagens de erro e mensagens de logout bem-sucedido.

## Página do Painel do Usuário

Este código HTML representa uma página de painel do usuário em um aplicativo da web. A página é projetada para ser exibida após o login bem-sucedido de um usuário, fornecendo informações personalizadas e opções de logout. O código faz uso da linguagem de modelo Thymeleaf para renderização dinâmica de dados e da segurança do Spring Security para controlar o acesso.

```html
<!DOCTYPE html>
<html lang="en" xmlns:th="http://www.thymeleaf.org">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Login Form</title>
    <link rel="stylesheet" th:href="@{../css/styles.css}">
  </head>
  <body>
    
    <div class="header">
      <h1>User Dashboard</h1>
    </div>
    
    <div class="container">
      <h2>Welcome, [[${user.getFullname()}]] !</h2>

      <span sec:authorize="isAuthenticated">
        <a th:href="@{/logout}" class="link-custom">Logout</a>
      </span>
    </div>

  </body>
</html>
```

**Imagem do Painel do Usuário**

 A página do painel do usuário é acessada através do seguinte link: `http://localhost:8080/user-page`. 

<p align="center">
  <img src=".\src\main\resources\static\img\page_user.png" alt="Painel do usuário" width=800/>
</p>

### Corpo da Página

  - `<h1>User Dashboard</h1>`: Um título principal que identifica a página como o "Painel do Usuário".

  - `<div class="container">`: Um contêiner principal para o conteúdo da página.

    - `<h2>Welcome, [[${user.getFullname()}]] !</h2>`: Uma mensagem de boas-vindas personalizada que exibe o nome completo do usuário. Os dados dinâmicos são injetados usando a sintaxe do Thymeleaf.

    - `<span sec:authorize="isAuthenticated">`: Uma seção condicional que verifica se o usuário está autenticado.

      - `<a th:href="@{/logout}" class="link-custom">Logout</a>`: Um link "Logout" que permite ao usuário fazer logout da sessão. O atributo `th:href` é usado para definir o URL de logout.

### Utilização

Este código HTML representa a página de boas-vindas do painel do usuário após o login bem-sucedido. Ela exibe o nome completo do usuário logado e fornece uma opção de logout. Essa página é acessada após o login bem-sucedido e é parte integrante de um aplicativo que requer autenticação.

## Página do Painel de Administrador

Este código HTML representa uma página de painel de administrador em um aplicativo da web. A página é projetada para ser exibida após o login bem-sucedido de um administrador, fornecendo informações personalizadas e opções de logout. O código faz uso da linguagem de modelo Thymeleaf para renderização dinâmica de dados e da segurança do Spring Security para controlar o acesso.

```html
<!DOCTYPE html>
<html lang="en" xmlns:th="http://www.thymeleaf.org">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Login Form</title>
    <link rel="stylesheet" th:href="@{../css/styles.css}">
  </head>
  <body>
    
    <div class="header">
      <h1>Admin Dashboard</h1>
    </div>
    
    <div class="container">
      <h2>Welcome, [[${user.getFullname()}]]!</h2>

      <span sec:authorize="isAuthenticated">
        <a th:href="@{/logout}" class="link-custom">Logout</a>
      </span>

    </div>

  </body>
</html>
```

**Imagem do Painel do Admin**

 A página do painel do admin é acessada através do seguinte link: `http://localhost:8080/admin-page`. 

<p align="center">
  <img src=".\src\main\resources\static\img\page_admin.png" alt="Painel do usuário" width=800/>
</p>

### Corpo da Página

   - `<h1>Admin Dashboard</h1>`: Um título principal que identifica a página como o "Painel de Administrador".

  - `<div class="container">`: Um contêiner principal para o conteúdo da página.

    - `<h2>Welcome, [[${user.getFullname()}]]!</h2>`: Uma mensagem de boas-vindas personalizada que exibe o nome completo do administrador. Os dados dinâmicos são injetados usando a sintaxe do Thymeleaf.

    - `<span sec:authorize="isAuthenticated">`: Uma seção condicional que verifica se o administrador está autenticado.

      - `<a th:href="@{/logout}" class="link-custom">Logout</a>`: Um link "Logout" que permite ao administrador fazer logout da sessão. O atributo `th:href` é usado para definir o URL de logout.

### Utilização

Este código HTML representa a página de boas-vindas do painel de administrador após o login bem-sucedido. Ela exibe o nome completo do administrador logado e fornece uma opção de logout. Essa página é acessada após o login bem-sucedido e é parte integrante de um aplicativo que requer autenticação de administrador.

## Conclusão

### Principais Componentes

#### Entidades

- `User`: A classe que representa um usuário no aplicativo. Ela armazena informações como email, senha, função (role) e nome completo.

#### Repositórios

- `UserRepository`: Um repositório JPA usado para acessar e gerenciar os dados de usuário no banco de dados.

#### DTO (Data Transfer Object)

- `UserDto`: Uma classe usada para transferir dados entre a camada de controle e a camada de serviço. Ela inclui informações como email, senha, função e nome completo.

#### Serviços

- `UserService`: Uma interface que define as operações relacionadas ao usuário, incluindo o método `save` para criar um novo usuário.

- `UserServiceImpl`: A implementação do serviço de usuário, que lida com a criação de usuários, criptografia de senhas e persistência no banco de dados.

- `CustomUserDetailService`: Um serviço que implementa a interface `UserDetailsService` do Spring Security para carregar informações de usuário com base no nome de usuário.

#### Classes de Segurança

- `CustomUserDetail`: Uma classe que implementa a interface `UserDetails` do Spring Security para fornecer detalhes do usuário durante a autenticação.

- `CustomSuccessHandler`: Uma classe que implementa a interface `AuthenticationSuccessHandler` para lidar com o redirecionamento após o login com base no papel do usuário.

#### Configuração de Segurança

- `SecurityConfig`: Uma classe de configuração que define as políticas de segurança, as URLs protegidas, as regras de autenticação e autorização, e os redirecionamentos após o login e o logout.

### Páginas HTML

O projeto inclui várias páginas HTML para a interface do usuário:

- Página de Registro (`register.html`): Permite aos usuários criar uma conta fornecendo informações pessoais, incluindo email, senha e nome completo.

- Página de Login (`login.html`): A página de login que permite aos usuários autenticar-se no aplicativo fornecendo suas credenciais.

- Página de Painel de Usuário (`user.html`): Uma página de boas-vindas personalizada para usuários autenticados, que exibe seu nome e fornece um link de logout.

- Página de Painel de Administrador (`admin.html`): Uma página semelhante à de usuário, mas direcionada aos administradores com funcionalidades adicionais.

### Fluxo do Aplicativo

- Um usuário pode acessar a página de registro para criar uma conta fornecendo informações pessoais.

- Após o registro bem-sucedido, o usuário é redirecionado para a página de login.

- Na página de login, o usuário fornece suas credenciais (email e senha).

- Após o login bem-sucedido, o usuário é redirecionado para a página de boas-vindas apropriada, dependendo de sua função (usuário ou administrador).

- A página de boas-vindas exibe o nome do usuário e oferece um link de logout.

- O usuário pode fazer logout a qualquer momento, o que o redireciona para a página de login.

# Autor
## **Feito por:** `Daniel Penelva de Andrade`



















