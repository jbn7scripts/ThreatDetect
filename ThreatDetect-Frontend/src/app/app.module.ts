import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';

import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { LoginComponent } from './components/login/login.component';
import {FormsModule} from "@angular/forms";
import { DashboardComponent } from './components/dashboard/dashboard.component';
import { HomeComponent } from './components/home/home.component';
import { AboutComponent } from './components/about/about.component';
import { RegisterComponent } from './components/register/register.component';
import { ModelSwitchComponent } from './components/model-switch/model-switch.component';
import {HTTP_INTERCEPTORS, HttpClientModule} from "@angular/common/http";



import { AuthInterceptor} from "./interceptors/auth.interceptor";
import {NgChartsModule} from "ng2-charts";
import { PredictComponent } from './components/predict/predict.component';
import { UploadComponent } from './components/upload/upload.component';
import {ChartComponent, NgApexchartsModule} from "ng-apexcharts";
@NgModule({
  declarations: [
    AppComponent,
    LoginComponent,
    DashboardComponent,
    HomeComponent,
    AboutComponent,
    RegisterComponent,
    ModelSwitchComponent,
    PredictComponent,
    UploadComponent
  ],
    imports: [
        BrowserModule,
        AppRoutingModule,
        FormsModule,
        NgChartsModule,
        HttpClientModule,
        ChartComponent,
        NgApexchartsModule

    ],
  providers: [
    {
      provide: HTTP_INTERCEPTORS,
      useClass: AuthInterceptor,
      multi: true,
    }
  ],
  bootstrap: [AppComponent]
})
export class AppModule { }
