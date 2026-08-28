import 'dart:io';

void main() async {
  var res = await Process.run('flutter', ['analyze'], workingDirectory: 'C:/SOC_AUTOMATION_PROJECT_FINAL/sentinelx_mobile');
  print('Exit code: ${res.exitCode}');
  print('Stdout:');
  print(res.stdout);
  print('Stderr:');
  print(res.stderr);
}
