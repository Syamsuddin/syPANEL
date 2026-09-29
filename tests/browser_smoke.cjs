// Optional browser integration test. Run ONLY against a disposable sandbox.
const {chromium}=require('playwright');
(async()=>{
 const base=process.env.SYPANEL_TEST_URL||'http://127.0.0.1:8080';
 const username=process.env.SYPANEL_TEST_USER||'admin';
 const password=process.env.SYPANEL_TEST_PASSWORD;
 if(!password)throw Error('Set SYPANEL_TEST_PASSWORD for an existing sandbox account.');
 const browser=await chromium.launch({headless:true});
 try {
  const context=await browser.newContext({viewport:{width:1440,height:1000}}),page=await context.newPage();
  const errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.goto(base);
  const info=await(await context.request.get(base+'/api/me')).json();
  if(info.mode!=='sandbox')throw Error('Refusing to run against live mode.');
  await page.locator('#login-form input[name=username]').fill(username);
  await page.locator('#login-form input[name=password]').fill(password);
  await page.locator('#login-form button').click();await page.locator('.hero').waitFor();
  const domain='qa-'+Date.now()+'.example.test';
  await page.locator('#page-actions button').click();await page.locator('#resource-form input[name=domain]').fill(domain);
  await page.locator('#resource-form select[name=php]').selectOption('static');
  await page.locator('#resource-form button[type=submit]').click();await page.locator('#dialog').waitFor({state:'hidden'});
  for(let i=0;i<30;i++){
   const data=await(await context.request.get(base+'/api/resources/sites')).json();
   if(data.some(x=>x.name===domain&&x.status==='active'))break;
   if(i===29)throw Error('Worker did not provision the test site.');
   await page.waitForTimeout(300);
  }
  for(const route of ['dashboard','sites','files','databases','dns','mailboxes','forwarders','ssl','backups','cron','sshkeys','redirects','services','logs','jobs','users','audit','settings']){
   await page.goto(base+'/#'+route);await page.locator('.loading').waitFor({state:'hidden'});
   if(await page.getByText('Data belum tersedia',{exact:true}).count())throw Error('Page failed: '+route);
  }
  await page.goto(base+'/#dashboard');await page.locator('.hero').waitFor();
  await page.setViewportSize({width:390,height:844});await page.waitForTimeout(350);
  if(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth))throw Error('Mobile overflow.');
  const side=await page.locator('#sidebar').boundingBox();if(side.x+side.width>1)throw Error('Mobile sidebar visible while closed.');
  if(errors.length)throw Error(errors.join('\n'));
  console.log('PASS: 18 routes, site provisioning, mobile layout. Test site retained:',domain);
 } finally {await browser.close()}
})().catch(e=>{console.error(e.message);process.exit(1)});
