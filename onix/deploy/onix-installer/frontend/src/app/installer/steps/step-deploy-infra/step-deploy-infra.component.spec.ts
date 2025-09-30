/**
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { ComponentFixture, TestBed, fakeAsync, tick } from '@angular/core/testing';
import { Router } from '@angular/router';
import { FormBuilder, ReactiveFormsModule } from '@angular/forms';
import { NoopAnimationsModule } from '@angular/platform-browser/animations';
import { BehaviorSubject, EMPTY, Subject, throwError } from 'rxjs';

import { StepDeployInfraComponent } from './step-deploy-infra.component';
import { InstallerStateService } from '../../../core/services/installer-state.service';
import { WebSocketService } from '../../../core/services/websocket.service';
import { ApiService } from '../../../core/services/api.service';
import { InstallerState, DeploymentStatus, InfraDetails } from '../../types/installer.types';

const initialMockState: InstallerState = {
  currentStepIndex: 4,
  installerGoal: 'create_new_open_network',
  prerequisitesMet: true,
  deploymentGoal: { all: true, gateway: false, registry: false, bap: false, bpp: false },
  gcpConfiguration: { projectId: 'test-project', region: 'us-central1' },
  appName: '',
  deploymentSize: 'small',
  deploymentStatus: 'pending',
  deploymentLogs: [],
  infraDetails: null,
  appExternalIp: null,
  globalDomainConfig: null,
  componentSubdomainPrefixes: [],
  subdomainConfigs: [],
  dockerImageConfigs: [],
  appSpecificConfigs: [],
  healthCheckStatuses: [],
  deployedServiceUrls: {},
  appDeployImageConfig: {
    registryImageUrl: '', registryAdminImageUrl: '', gatewayImageUrl: '', adapterImageUrl: '', subscriptionImageUrl: ''
  },
  appDeployRegistryConfig: {
    registryUrl: '', registryKeyId: '', registrySubscriberId: '', enableAutoApprover: false
  },
  appDeployGatewayConfig: { gatewaySubscriptionId: '' },
  appDeployAdapterConfig: { enableSchemaValidation: false },
  highestStepReached: 4,
  appDeploymentStatus: 'pending',
  servicesDeployed: [],
  logsExplorerUrls: {}
};


class MockInstallerStateService {
  private state = new BehaviorSubject<InstallerState>(initialMockState);

  installerState$ = this.state.asObservable();

  getCurrentState = () => this.state.getValue();
  updateAppNameAndSize = jasmine.createSpy('updateAppNameAndSize');
  updateDeploymentStatus = jasmine.createSpy('updateDeploymentStatus').and.callFake((status: DeploymentStatus) => {
    const currentState = this.state.getValue();
    this.state.next({ ...currentState, deploymentStatus: status });
  });
  addDeploymentLog = jasmine.createSpy('addDeploymentLog');
  clearDeploymentLogs = jasmine.createSpy('clearDeploymentLogs');
  setInfraDetails = jasmine.createSpy('setInfraDetails');
  setAppExternalIp = jasmine.createSpy('setAppExternalIp');
}

class MockWebSocketService {
  connectionSubject = new Subject<any>();
  connect = jasmine.createSpy('connect').and.returnValue(this.connectionSubject.asObservable());
  sendMessage = jasmine.createSpy('sendMessage');
  closeConnection = jasmine.createSpy('closeConnection');

  // Helper to simulate receiving a message
  receiveMessage(message: any) {
    this.connectionSubject.next(message);
  }

  // Helper to simulate an error
  simulateError(error: any) {
    this.connectionSubject.error(error);
  }
}

describe('StepDeployInfraComponent', () => {
  let component: StepDeployInfraComponent;
  let fixture: ComponentFixture<StepDeployInfraComponent>;
  let installerStateService: MockInstallerStateService;
  let webSocketService: MockWebSocketService;
  let router: Router;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [
        StepDeployInfraComponent,
        ReactiveFormsModule,
        NoopAnimationsModule
      ],
      providers: [
        FormBuilder,
        { provide: InstallerStateService, useClass: MockInstallerStateService },
        { provide: WebSocketService, useClass: MockWebSocketService },
        { provide: ApiService, useValue: {} },
        { provide: Router, useValue: { navigate: jasmine.createSpy('navigate') } }
      ]
    }).compileComponents();

    fixture = TestBed.createComponent(StepDeployInfraComponent);
    component = fixture.componentInstance;
    installerStateService = TestBed.inject(InstallerStateService) as any;
    webSocketService = TestBed.inject(WebSocketService) as any;
    router = TestBed.inject(Router);

    fixture.detectChanges();
  });

  it('should create and initialize the form', () => {
    expect(component).toBeTruthy();
    expect(component.deployInfraForm).toBeDefined();
    expect(component.deployInfraForm.get('appName')).toBeDefined();
    expect(component.deployInfraForm.get('deploymentSize')).toBeDefined();
  });

  it('should update state service on form value changes', fakeAsync(() => {
    component.deployInfraForm.patchValue({ appName: 'onix', deploymentSize: 'medium' });
    tick(300); // Wait for debounceTime
    expect(installerStateService.updateAppNameAndSize).toHaveBeenCalledWith('onix', 'medium');
  }));

  describe('onDeployInfra', () => {
    beforeEach(() => {
      // Set the installerGoal to ensure component properties are correctly derived
      const state = installerStateService.getCurrentState();
      state.deploymentGoal = { all: true, gateway: true, registry: true, bap: true, bpp: true };
      component.deployInfraForm.setValue({ appName: 'onix', deploymentSize: 'small' });
      fixture.detectChanges();
    });

    it('should not deploy if form is invalid', () => {
      component.deployInfraForm.get('appName')?.setValue('');
      component.onDeployInfra();
      expect(webSocketService.connect).not.toHaveBeenCalled();
    });

    it('should not deploy if GCP configuration is missing', () => {
        spyOn(installerStateService, 'getCurrentState').and.returnValue({ ...initialMockState, gcpConfiguration: null });
        component.onDeployInfra();
        expect(webSocketService.connect).not.toHaveBeenCalled();
    });

    it('should initiate deployment, update status, and connect to WebSocket', () => {
      component.onDeployInfra();

      expect(installerStateService.updateDeploymentStatus).toHaveBeenCalledWith('in-progress');
      expect(installerStateService.clearDeploymentLogs).toHaveBeenCalled();
      expect(installerStateService.addDeploymentLog).toHaveBeenCalledWith('Initiating infrastructure deployment...');
      expect(webSocketService.connect).toHaveBeenCalledWith('ws://127.0.0.1:8000/ws/deployInfra');

      const expectedPayload = {
        project_id: 'test-project',
        region: 'us-central1',
        app_name: 'onix',
        type: 'small',
        components: { gateway: true, registry: true, bap: true, bpp: true }
      };
      expect(webSocketService.sendMessage).toHaveBeenCalledWith(expectedPayload);
    });

    it('should handle WebSocket log messages', () => {
        component.onDeployInfra();
        const logMessage = { type: 'log', message: 'Terraform init...' };
        webSocketService.receiveMessage(JSON.stringify(logMessage));
        fixture.detectChanges();
        expect(installerStateService.addDeploymentLog).toHaveBeenCalledWith('Terraform init...');
    });

    it('should handle WebSocket success message and set infra details', () => {
        component.onDeployInfra();
        const successPayload: InfraDetails = {
            'global_ip_address': { value: '123.45.67.89' },
            'cluster_name': { value: 'onix-cluster' }
        };
        const successMessage = { type: 'success', message: successPayload };

        webSocketService.receiveMessage(JSON.stringify(successMessage));
        fixture.detectChanges();

        expect(installerStateService.updateDeploymentStatus).toHaveBeenCalledWith('completed');
        expect(installerStateService.addDeploymentLog).toHaveBeenCalledWith('Infrastructure Deployment Completed Successfully!');
        expect(installerStateService.setInfraDetails).toHaveBeenCalledWith(successPayload);
        expect(installerStateService.setAppExternalIp).toHaveBeenCalledWith('123.45.67.89');
        expect(webSocketService.closeConnection).toHaveBeenCalled();
    });

    it('should handle WebSocket error message', () => {
        component.onDeployInfra();
        const errorMessage = { type: 'error', message: 'Terraform apply failed.' };
        webSocketService.receiveMessage(JSON.stringify(errorMessage));
        fixture.detectChanges();

        expect(installerStateService.updateDeploymentStatus).toHaveBeenCalledWith('failed');
        expect(installerStateService.addDeploymentLog).toHaveBeenCalledWith('Infrastructure Deployment Failed: Terraform apply failed.');
        expect(webSocketService.closeConnection).toHaveBeenCalled();
    });

    it('should handle WebSocket connection error', () => {
        const error = new Error('Connection failed');
        webSocketService.connect.and.returnValue(throwError(() => error));

        component.onDeployInfra();
        fixture.detectChanges();

        expect(installerStateService.updateDeploymentStatus).toHaveBeenCalledWith('failed');
        expect(installerStateService.addDeploymentLog).toHaveBeenCalledWith(`WebSocket connection error: ${error.message}`);
    });
  });

  describe('Navigation', () => {
    it('onBack should navigate to gcp-connection', () => {
      component.onBack();
      expect(router.navigate).toHaveBeenCalledWith(['installer', 'gcp-connection']);
    });

    it('onNext should not navigate if deployment is not complete', () => {
      component.onNext();
      expect(router.navigate).not.toHaveBeenCalled();
    });

    it('onNext should navigate to domain-configuration when deployment is complete', () => {
      installerStateService.updateDeploymentStatus('completed');
      fixture.detectChanges();

      component.onNext();
      expect(router.navigate).toHaveBeenCalledWith(['installer', 'domain-configuration']);
    });
  });
});