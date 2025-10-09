// lib/main.dart

import 'package:flutter/material.dart';
import 'package:dio/dio.dart';
import 'package:dio_cookie_manager/dio_cookie_manager.dart';
import 'package:cookie_jar/cookie_jar.dart';

// ===================================================================
// SERVIÇO DE API (Sem alterações)
// ===================================================================
class ApiService {
  final Dio dio;
  static final ApiService _instance = ApiService._internal();
  factory ApiService() => _instance;
  ApiService._internal() : dio = Dio() {
    final cookieJar = CookieJar();
    dio.interceptors.add(CookieManager(cookieJar));
    dio.options.baseUrl = 'https://condoiq.onrender.com';
  }
}

// Ponto de entrada do App
void main() => runApp(const CondoIQApp());

class CondoIQApp extends StatelessWidget {
  const CondoIQApp({super.key});
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'CondoIQ',
      theme: ThemeData(
        primarySwatch: Colors.blueGrey,
        useMaterial3: true,
        scaffoldBackgroundColor: Colors.grey[100],
        appBarTheme: const AppBarTheme(
          backgroundColor: Color(0xFF263238), // blueGrey[900]
          foregroundColor: Colors.white,
          elevation: 4,
        ),
      ),
      debugShowCheckedModeBanner: false,
      home: const LoginPage(),
    );
  }
}

// ===================================================================
// TELA DE LOGIN (Sem alterações)
// ===================================================================
class LoginPage extends StatefulWidget {
  const LoginPage({super.key});
  @override
  State<LoginPage> createState() => _LoginPageState();
}
class _LoginPageState extends State<LoginPage> {
  final apiService = ApiService();
  final _emailController = TextEditingController();
  final _passwordController = TextEditingController();
  String _message = '';
  bool _isLoading = false;

  Future<void> _login() async {
    setState(() { _isLoading = true; _message = ''; });
    try {
      final response = await apiService.dio.post('/api/login', data: {
        'email': _emailController.text, 'senha': _passwordController.text
      });
      if (response.statusCode == 200 && response.data['success'] == true) {
        Navigator.of(context).pushReplacement(
          MaterialPageRoute(builder: (context) => DashboardPage(user: response.data['user'])),
        );
      }
    } on DioException catch (e) {
      _message = e.response?.data['message'] ?? 'Erro de conexão.';
    }
    if (mounted) setState(() { _isLoading = false; });
  }

  @override
  Widget build(BuildContext context) => Scaffold(
    body: Center(child: SingleChildScrollView(padding: const EdgeInsets.all(24.0), child: Column(mainAxisAlignment: MainAxisAlignment.center, children: [
      const Text('CondoIQ', style: TextStyle(fontSize: 32, fontWeight: FontWeight.bold, color: Color(0xFF263238))),
      const SizedBox(height: 40),
      TextField(controller: _emailController, decoration: const InputDecoration(labelText: 'Email', border: OutlineInputBorder(), prefixIcon: Icon(Icons.email)), keyboardType: TextInputType.emailAddress),
      const SizedBox(height: 12),
      TextField(controller: _passwordController, decoration: const InputDecoration(labelText: 'Senha', border: OutlineInputBorder(), prefixIcon: Icon(Icons.lock)), obscureText: true),
      const SizedBox(height: 20),
      _isLoading ? const CircularProgressIndicator() : ElevatedButton(style: ElevatedButton.styleFrom(minimumSize: const Size(double.infinity, 50), backgroundColor: const Color(0xFF263238), foregroundColor: Colors.white, shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8))), onPressed: _login, child: const Text('Entrar', style: TextStyle(fontSize: 16))),
      const SizedBox(height: 20),
      Text(_message, style: const TextStyle(color: Colors.red, fontWeight: FontWeight.bold)),
    ]))),
  );
}


// ===================================================================
// ALTERADO: DASHBOARD AGORA É O MENU PRINCIPAL
// ===================================================================
class DashboardPage extends StatelessWidget {
  final Map<String, dynamic> user;
  const DashboardPage({super.key, required this.user});

  void _logout(BuildContext context) async {
    try { await ApiService().dio.post('/api/logout'); } catch (e) {/* Ignora */}
    Navigator.of(context).pushAndRemoveUntil(
      MaterialPageRoute(builder: (context) => const LoginPage()), (route) => false);
  }
  
  @override
  Widget build(BuildContext context) {
    String nomeUsuario = user['nome'] ?? 'Usuário';
    return Scaffold(
      appBar: AppBar(
        title: Text("Bem-vindo, $nomeUsuario"),
        actions: [IconButton(icon: const Icon(Icons.logout), onPressed: () => _logout(context))],
      ),
      body: GridView.count(
        crossAxisCount: 2, // 2 colunas
        padding: const EdgeInsets.all(16.0),
        crossAxisSpacing: 16.0,
        mainAxisSpacing: 16.0,
        children: <Widget>[
          _MenuItem(
            title: 'Comunicados',
            icon: Icons.campaign,
            onTap: () => Navigator.push(context, MaterialPageRoute(builder: (_) => const ComunicadosPage())),
          ),
          _MenuItem(
            title: 'Abrir Portão',
            icon: Icons.garage,
            onTap: () => Navigator.push(context, MaterialPageRoute(builder: (_) => const AbrirPortaoPage())),
          ),
          _MenuItem(
            title: 'Info Condomínio',
            icon: Icons.apartment,
            onTap: () => Navigator.push(context, MaterialPageRoute(builder: (_) => const InfoCondominioPage())),
          ),
          _MenuItem(
            title: 'Abrir Reclamação',
            icon: Icons.report_problem,
            onTap: () => Navigator.push(context, MaterialPageRoute(builder: (_) => const AbrirReclamacaoPage())),
          ),
        ],
      ),
    );
  }
}

class _MenuItem extends StatelessWidget {
  final String title;
  final IconData icon;
  final VoidCallback onTap;
  const _MenuItem({required this.title, required this.icon, required this.onTap});

  @override
  Widget build(BuildContext context) {
    return Card(
      elevation: 4.0,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(12),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: <Widget>[
            Icon(icon, size: 48.0, color: Theme.of(context).primaryColor),
            const SizedBox(height: 12.0),
            Text(title, textAlign: TextAlign.center, style: const TextStyle(fontWeight: FontWeight.bold)),
          ],
        ),
      ),
    );
  }
}


// ===================================================================
// NOVA TELA: PÁGINA DE COMUNICADOS
// ===================================================================
class ComunicadosPage extends StatefulWidget {
  const ComunicadosPage({super.key});
  @override
  State<ComunicadosPage> createState() => _ComunicadosPageState();
}
class _ComunicadosPageState extends State<ComunicadosPage> {
  final apiService = ApiService();
  bool _isLoading = true;
  String? _error;
  List<dynamic> _comunicados = [];

  @override
  void initState() {
    super.initState();
    _fetchDashboardData();
  }

  Future<void> _fetchDashboardData() async {
    try {
      final response = await apiService.dio.get('/api/dashboard');
      if (response.statusCode == 200) {
        setState(() {
          _comunicados = response.data['comunicados'];
          _isLoading = false;
        });
      }
    } catch (e) {
      setState(() { _error = "Erro de conexão"; _isLoading = false; });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text("Comunicados")),
      body: _buildBody(),
    );
  }

  Widget _buildBody() {
    if (_isLoading) return const Center(child: CircularProgressIndicator());
    if (_error != null) return Center(child: Text(_error!));
    if (_comunicados.isEmpty) return const Center(child: Text("Nenhum comunicado no momento."));

    return ListView.builder(
      padding: const EdgeInsets.all(8.0),
      itemCount: _comunicados.length,
      itemBuilder: (context, index) {
        final c = _comunicados[index];
        return Card(
          elevation: 2,
          margin: const EdgeInsets.symmetric(vertical: 8.0),
          child: ListTile(
            title: Text(c['titulo'], style: const TextStyle(fontWeight: FontWeight.bold)),
            subtitle: Padding(padding: const EdgeInsets.only(top: 8.0), child: Text(c['conteudo'])),
            isThreeLine: true,
          ),
        );
      },
    );
  }
}


// ===================================================================
// NOVA TELA: PÁGINA PARA ABRIR O PORTÃO
// ===================================================================
class AbrirPortaoPage extends StatefulWidget {
  const AbrirPortaoPage({super.key});
  @override
  State<AbrirPortaoPage> createState() => _AbrirPortaoPageState();
}
class _AbrirPortaoPageState extends State<AbrirPortaoPage> {
  final apiService = ApiService();
  bool _isLoading = false;

  void _abrirPortao() async {
    setState(() => _isLoading = true);
    try {
      final response = await apiService.dio.post('/api/abrir_portao');
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(
        content: Text(response.data['message']),
        backgroundColor: Colors.green,
      ));
    } on DioException catch (e) {
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(
        content: Text(e.response?.data['message'] ?? "Erro de conexão"),
        backgroundColor: Colors.red,
      ));
    }
    setState(() => _isLoading = false);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text("Abrir Portão")),
      body: Center(
        child: _isLoading
          ? const CircularProgressIndicator()
          : ElevatedButton.icon(
              icon: const Icon(Icons.garage, size: 32),
              label: const Text("ABRIR", style: TextStyle(fontSize: 24)),
              style: ElevatedButton.styleFrom(
                padding: const EdgeInsets.symmetric(horizontal: 40, vertical: 20),
                backgroundColor: const Color(0xFF263238),
                foregroundColor: Colors.white,
              ),
              onPressed: _abrirPortao,
            ),
      ),
    );
  }
}

// ===================================================================
// NOVA TELA: INFORMAÇÕES DO CONDOMÍNIO
// ===================================================================
class InfoCondominioPage extends StatefulWidget {
  const InfoCondominioPage({super.key});
  @override
  State<InfoCondominioPage> createState() => _InfoCondominioPageState();
}
class _InfoCondominioPageState extends State<InfoCondominioPage> {
    final apiService = ApiService();
    bool _isLoading = true;
    String? _error;
    Map<String, dynamic> _condoInfo = {};

    @override
    void initState() {
      super.initState();
      _fetchDashboardData();
    }

    Future<void> _fetchDashboardData() async {
      try {
        final response = await apiService.dio.get('/api/dashboard');
        if (response.statusCode == 200) {
          setState(() {
            _condoInfo = response.data['condominio'];
            _isLoading = false;
          });
        }
      } catch (e) {
        setState(() { _error = "Erro de conexão"; _isLoading = false; });
      }
    }
    
    @override
    Widget build(BuildContext context) {
      return Scaffold(
        appBar: AppBar(title: const Text("Informações do Condomínio")),
        body: _isLoading 
            ? const Center(child: CircularProgressIndicator())
            : _error != null 
                ? Center(child: Text(_error!))
                : Padding(
                  padding: const EdgeInsets.all(16.0),
                  child: ListTile(
                    leading: const Icon(Icons.apartment, size: 40),
                    title: Text(_condoInfo['nome'] ?? 'Não informado', style: const TextStyle(fontSize: 20, fontWeight: FontWeight.bold)),
                    subtitle: Text(_condoInfo['endereco'] ?? 'Não informado', style: const TextStyle(fontSize: 16)),
                  ),
                ),
      );
    }
}


// ===================================================================
// NOVA TELA: ABRIR RECLAMAÇÃO
// ===================================================================
class AbrirReclamacaoPage extends StatefulWidget {
  const AbrirReclamacaoPage({super.key});
  @override
  State<AbrirReclamacaoPage> createState() => _AbrirReclamacaoPageState();
}
class _AbrirReclamacaoPageState extends State<AbrirReclamacaoPage> {
  final apiService = ApiService();
  final _titleController = TextEditingController();
  final _descController = TextEditingController();
  bool _isLoading = false;

  void _enviarReclamacao() async {
    if (_titleController.text.isEmpty || _descController.text.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(
        content: Text("Por favor, preencha todos os campos."),
        backgroundColor: Colors.orange,
      ));
      return;
    }

    setState(() => _isLoading = true);
    try {
      await apiService.dio.post('/api/abrir_reclamacao', data: {
        'titulo': _titleController.text,
        'descricao': _descController.text,
      });
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(
        content: Text("Reclamação enviada com sucesso!"),
        backgroundColor: Colors.green,
      ));
      Navigator.of(context).pop(); // Volta para o menu
    } on DioException catch (e) {
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(
        content: Text(e.response?.data['message'] ?? "Erro de conexão"),
        backgroundColor: Colors.red,
      ));
    }
    setState(() => _isLoading = false);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text("Abrir Reclamação")),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          children: [
            TextField(controller: _titleController, decoration: const InputDecoration(labelText: 'Título', border: OutlineInputBorder())),
            const SizedBox(height: 16),
            TextField(controller: _descController, decoration: const InputDecoration(labelText: 'Descrição', border: OutlineInputBorder()), maxLines: 5),
            const SizedBox(height: 24),
            _isLoading
                ? const CircularProgressIndicator()
                : ElevatedButton(
                    style: ElevatedButton.styleFrom(minimumSize: const Size(double.infinity, 50)),
                    onPressed: _enviarReclamacao,
                    child: const Text("Enviar"),
                  ),
          ],
        ),
      ),
    );
  }
}