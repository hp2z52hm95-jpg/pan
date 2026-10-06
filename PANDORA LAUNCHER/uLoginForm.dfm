object LoginForm: TLoginForm
  Left = 0
  Top = 0
  BorderStyle = bsDialog
  Caption = 'Pandora Tool - Sign in'
  ClientHeight = 361
  ClientWidth = 380
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -12
  Font.Name = 'Segoe UI'
  Font.Style = []
  Position = poScreenCenter
  TextHeight = 15
  object lblTitle: TLabel
    Left = 24
    Top = 16
    Width = 332
    Height = 25
    Alignment = taCenter
    AutoSize = False
    Caption = 'Sign in to Pandora Tool'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -16
    Font.Name = 'Segoe UI'
    Font.Style = [fsBold]
    ParentFont = False
  end
  object lblUser: TLabel
    Left = 24
    Top = 56
    Width = 55
    Height = 15
    Caption = 'Username'
  end
  object edtUsername: TEdit
    Left = 24
    Top = 74
    Width = 332
    Height = 27
    TabOrder = 0
  end
  object lblPass: TLabel
    Left = 24
    Top = 112
    Width = 50
    Height = 15
    Caption = 'Password'
  end
  object edtPassword: TEdit
    Left = 24
    Top = 130
    Width = 332
    Height = 27
    PasswordChar = '*'
    TabOrder = 1
  end
  object btnLogin: TButton
    Left = 24
    Top = 172
    Width = 332
    Height = 34
    Caption = 'Sign in'
    Default = True
    TabOrder = 2
    OnClick = btnLoginClick
  end
  object btnPasskey: TButton
    Left = 24
    Top = 214
    Width = 332
    Height = 34
    Caption = 'Sign in with passkey'
    TabOrder = 3
    OnClick = btnPasskeyClick
  end
  object btnCancel: TButton
    Left = 24
    Top = 256
    Width = 332
    Height = 28
    Cancel = True
    Caption = 'Cancel'
    ModalResult = 2
    TabOrder = 4
  end
  object lblStatus: TLabel
    Left = 24
    Top = 296
    Width = 332
    Height = 52
    AutoSize = False
    WordWrap = True
  end
end
