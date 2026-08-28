const { Builder, By, until } = require('selenium-webdriver');

async function runLoginTest() {
    let driver = await new Builder().forBrowser('chrome').build();
    try {
        await driver.get('http://localhost:3000/spa.html');
        // Click Create Account / Login toggle if needed
        let userField = await driver.findElement(By.id('LOG_U'));
        let passField = await driver.findElement(By.id('LOG_P'));
        await userField.sendKeys('admin');
        await passField.sendKeys('admin');
        
        let loginBtn = await driver.findElement(By.id('LOGIN_SUBMIT_BTN'));
        await loginBtn.click();
        
        // Wait for dashboard to load
        await driver.wait(until.elementLocated(By.id('DASHBOARD_ELEMENT')), 5000);
        console.log('Login test passed');
    } finally {
        await driver.quit();
    }
}
runLoginTest();
