object Form1: TForm1
  Left = 0
  Top = 0
  Caption = 'Passkey Authentication - Smoke Test'
  ClientHeight = 620
  ClientWidth = 780
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -12
  Font.Name = 'Segoe UI'
  Font.Style = []
  Position = poScreenCenter
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  TextHeight = 15
  object PanelTop: TPanel
    Left = 0
    Top = 0
    Width = 780
    Height = 100
    Align = alTop
    BevelOuter = bvNone
    Color = clWhite
    TabOrder = 0
    object LabelTitle: TLabel
      Left = 20
      Top = 15
      Width = 350
      Height = 25
      Caption = 'Passkey Authentication (FIDO2/WebAuthn)'
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clBlack
      Font.Height = -18
      Font.Name = 'Segoe UI'
      Font.Style = [fsBold]
      ParentFont = False
    end
    object LabelSubtitle: TLabel
      Left = 20
      Top = 45
      Width = 500
      Height = 17
      Caption = 'Smoke Test using Windows Hello PIN (no fingerprint hardware required)'
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clGray
      Font.Height = -13
      Font.Name = 'Segoe UI'
      Font.Style = []
      ParentFont = False
    end
  end
  object GroupStatus: TGroupBox
    Left = 20
    Top = 110
    Width = 740
    Height = 80
    Caption = 'System Status'
    TabOrder = 1
    object LabelWebAuthn: TLabel
      Left = 20
      Top = 25
      Width = 150
      Height = 17
      Caption = 'WebAuthn API:'
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clBlack
      Font.Height = -13
      Font.Name = 'Segoe UI'
      Font.Style = [fsBold]
      ParentFont = False
    end
    object LabelWebAuthnStatus: TLabel
      Left = 180
      Top = 25
      Width = 100
      Height = 17
      Caption = 'Checking...'
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clGray
      Font.Height = -13
      Font.Name = 'Segoe UI'
      Font.Style = []
      ParentFont = False
    end
    object LabelPlatform: TLabel
      Left = 20
      Top = 50
      Width = 150
      Height = 17
      Caption = 'Windows Hello:'
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clBlack
      Font.Height = -13
      Font.Name = 'Segoe UI'
      Font.Style = [fsBold]
      ParentFont = False
    end
    object LabelPlatformStatus: TLabel
      Left = 180
      Top = 50
      Width = 100
      Height = 17
      Caption = 'Checking...'
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clGray
      Font.Height = -13
      Font.Name = 'Segoe UI'
      Font.Style = []
      ParentFont = False
    end
  end
  object GroupUser: TGroupBox
    Left = 20
    Top = 200
    Width = 740
    Height = 90
    Caption = 'User Configuration'
    TabOrder = 2
    object LabelUserId: TLabel
      Left = 20
      Top = 30
      Width = 60
      Height = 17
      Caption = 'User ID:'
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clBlack
      Font.Height = -13
      Font.Name = 'Segoe UI'
      Font.Style = [fsBold]
      ParentFont = False
    end
    object LabelUserName: TLabel
      Left = 20
      Top = 60
      Width = 80
      Height = 17
      Caption = 'User Name:'
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clBlack
      Font.Height = -13
      Font.Name = 'Segoe UI'
      Font.Style = [fsBold]
      ParentFont = False
    end
    object EditUserId: TEdit
      Left = 120
      Top = 27
      Width = 200
      Height = 25
      TabOrder = 0
      Text = 'user123'
    end
    object EditUserName: TEdit
      Left = 120
      Top = 57
      Width = 200
      Height = 25
      TabOrder = 1
      Text = 'Test User'
    end
  end
  object GroupActions: TGroupBox
    Left = 20
    Top = 300
    Width = 740
    Height = 100
    Caption = 'Passkey Operations'
    TabOrder = 3
    object BtnRegister: TButton
      Left = 20
      Top = 30
      Width = 200
      Height = 50
      Caption = 'Register Passkey'
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clWhite
      Font.Height = -14
      Font.Name = 'Segoe UI'
      Font.Style = [fsBold]
      ParentFont = False
      TabOrder = 0
      OnClick = BtnRegisterClick
    end
    object BtnAuthenticate: TButton
      Left = 240
      Top = 30
      Width = 200
      Height = 50
      Caption = 'Authenticate'
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clWhite
      Font.Height = -14
      Font.Name = 'Segoe UI'
      Font.Style = [fsBold]
      ParentFont = False
      TabOrder = 1
      OnClick = BtnAuthenticateClick
    end
    object BtnListCredentials: TButton
      Left = 460
      Top = 30
      Width = 200
      Height = 50
      Caption = 'List Passkeys'
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clBlack
      Font.Height = -14
      Font.Name = 'Segoe UI'
      Font.Style = []
      ParentFont = False
      TabOrder = 2
      OnClick = BtnListCredentialsClick
    end
  end
  object GroupLog: TGroupBox
    Left = 20
    Top = 410
    Width = 740
    Height = 195
    Caption = 'Activity Log'
    TabOrder = 4
    object MemoLog: TMemo
      Left = 10
      Top = 20
      Width = 720
      Height = 165
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clBlack
      Font.Height = -12
      Font.Name = 'Consolas'
      Font.Style = []
      ParentFont = False
      ReadOnly = True
      ScrollBars = ssBoth
      TabOrder = 0
    end
  end
end
