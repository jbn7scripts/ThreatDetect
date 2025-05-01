import { ComponentFixture, TestBed } from '@angular/core/testing';

import { ModelSwitchComponent } from './model-switch.component';

describe('ModelSwitchComponent', () => {
  let component: ModelSwitchComponent;
  let fixture: ComponentFixture<ModelSwitchComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [ModelSwitchComponent]
    })
    .compileComponents();
    
    fixture = TestBed.createComponent(ModelSwitchComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
