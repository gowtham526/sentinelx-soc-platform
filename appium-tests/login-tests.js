const wdio = require('webdriverio');

const opts = {
  path: '/wd/hub',
  port: 4723,
  capabilities: {
    platformName: 'Android',
    platformVersion: '11.0',
    deviceName: 'Android Emulator',
    app: '/path/to/app-debug.apk',
    automationName: 'UiAutomator2'
  }
};

async function main () {
  const client = await wdio.remote(opts);
  
  const userField = await client.$('~username_input');
  await userField.setValue('admin');
  
  const passField = await client.$('~password_input');
  await passField.setValue('admin');
  
  const loginBtn = await client.$('~login_button');
  await loginBtn.click();
  
  await client.pause(2000);
  await client.deleteSession();
}
main();
