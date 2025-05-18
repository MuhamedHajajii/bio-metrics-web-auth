import { ComponentFixture, TestBed } from '@angular/core/testing';

import { AuthControllerComponent } from './auth-controller.component';

describe('AuthControllerComponent', () => {
  let component: AuthControllerComponent;
  let fixture: ComponentFixture<AuthControllerComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [AuthControllerComponent]
    })
    .compileComponents();
    
    fixture = TestBed.createComponent(AuthControllerComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
