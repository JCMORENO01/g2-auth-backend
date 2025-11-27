package co.edu.javeriana.prestamos.service;

import co.edu.javeriana.prestamos.dto.*;
import co.edu.javeriana.prestamos.exception.AuthException;
import co.edu.javeriana.prestamos.exception.ValidationException;
import co.edu.javeriana.prestamos.model.Usuario;
import co.edu.javeriana.prestamos.model.RefreshToken;
import co.edu.javeriana.prestamos.repository.UsuarioRepository;
import co.edu.javeriana.prestamos.security.CustomUserDetails;
import co.edu.javeriana.prestamos.security.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UsuarioRepository usuarioRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final TokenService tokenService; // <--- Inyectamos tu TokenService

    @Transactional
    public AuthResponse register(RegisterRequest request) throws ValidationException {
        // ... (Tus validaciones existen igual, mantenlas) ...
        if (usuarioRepository.existsByUsername(request.getUsername())) {
            throw new ValidationException("El username ya está en uso");
        }
        if (usuarioRepository.existsByEmail(request.getEmail())) {
            throw new ValidationException("El email ya está registrado");
        }

        Usuario usuario = new Usuario();
        usuario.setNombre(request.getNombre());
        usuario.setUsername(request.getUsername());
        usuario.setEmail(request.getEmail());
        usuario.setContrasena(passwordEncoder.encode(request.getContrasena()));
        usuario.setId_tipo_usuario(request.getId_tipo_usuario());
        
        // CAMBIO CLAVE: Usuario nace INACTIVO (0) para verificar email
        usuario.setId_estado_usuario(1); 
        
        Usuario usuarioGuardado = usuarioRepository.save(usuario);

        
        return AuthResponse.builder()
                .id_usuario(usuarioGuardado.getId_usuario())
                .mensaje("Registro exitoso. Por favor verifique su email para activar la cuenta.")
                .build();
    }

    @Transactional
    public AuthResponse login(LoginRequest request) throws AuthException {
        Usuario usuario = usuarioRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new AuthException("Credenciales inválidas"));

        if (usuario.getId_estado_usuario() == 0) {
            throw new AuthException("Cuenta inactiva. Verifique su email.");
        }
        //

        try {
            authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getContrasena())
            );
            

            usuario.setIntentos_fallidos(0);
            usuarioRepository.save(usuario);
            
            CustomUserDetails userDetails = new CustomUserDetails(usuario);
            String jwtToken = jwtService.generateToken(userDetails);

            RefreshToken refreshToken = tokenService.createRefreshToken(usuario);

            return AuthResponse.builder()
                    .id_usuario(usuario.getId_usuario())
                    .token(jwtToken)
                    .refreshToken(refreshToken.getToken()) 
                    .mensaje("Login exitoso")
                    .usuario_info(buildUserInfo(usuario))
                    .permisos(getPermisosArray(usuario.getId_tipo_usuario()))
                    .build();

        } catch (BadCredentialsException e) {
            throw new AuthException("Credenciales incorrectas");
        }
    }

    public AuthResponse refreshToken(String requestRefreshToken) throws AuthException {
        RefreshToken rt = tokenService.findByToken(requestRefreshToken);
        if (rt == null || rt.isRevoked()) {
             throw new AuthException("Refresh token inválido o revocado");
        }
        
        Usuario usuario = rt.getUsuario();
        String newToken = jwtService.generateToken(new CustomUserDetails(usuario));
        
        return AuthResponse.builder()
                .token(newToken)
                .refreshToken(requestRefreshToken)
                .mensaje("Token renovado exitosamente")
                .build();
    }
    private UserInfo buildUserInfo(Usuario usuario) {
        return UserInfo.builder()
                .id_usuario(usuario.getId_usuario())
                .nombre(usuario.getNombre())
                .username(usuario.getUsername())
                .email(usuario.getEmail())
                .id_tipo_usuario(usuario.getId_tipo_usuario())
                .tipo_usuario(getTipoUsuarioNombre(usuario.getId_tipo_usuario()))
                .build();
    }

    private String getTipoUsuarioNombre(Integer tipoId) {
        switch (tipoId) {
            case 1: return "Estudiante";
            case 2: return "Bibliotecario";
            case 3: return "Admin";
            default: return "Estudiante";
        }
    }

    private String[] getPermisosArray(Integer tipoId) {
        switch (tipoId) {
            case 1: return new String[]{"VER_CATALOGO", "SOLICITAR_PRESTAMO", "VER_MIS_PRESTAMOS"};
            case 2: return new String[]{"VER_CATALOGO", "SOLICITAR_PRESTAMO", "VER_MIS_PRESTAMOS", 
                                       "APROBAR_PRESTAMO", "GESTIONAR_LIBROS", "VER_TODOS_PRESTAMOS"};
            case 3: return new String[]{"VER_CATALOGO", "SOLICITAR_PRESTAMO", "VER_MIS_PRESTAMOS", 
                                       "APROBAR_PRESTAMO", "GESTIONAR_LIBROS", "VER_TODOS_PRESTAMOS", 
                                       "GESTIONAR_USUARIOS", "VER_REPORTES"};
            default: return new String[]{"VER_CATALOGO"};
        }
    }
}
