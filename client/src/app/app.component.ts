import { Component, OnInit } from '@angular/core';
import { environment } from 'src/environments/environment';
declare var JSEncrypt: any;

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.scss']
})
export class AppComponent implements OnInit {
  title = 'client';

  ngOnInit(): void {
    const jsEncrypt = new JSEncrypt() as any;
    jsEncrypt.setPublicKey(environment.publicKey);
    const encrypted = jsEncrypt.encrypt('SURASAK');
    console.log(`encrypted data: ${encrypted}`);
  }
}
