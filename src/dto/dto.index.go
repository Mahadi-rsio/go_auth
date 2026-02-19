package dto

type SignUpBody struct {
	Email    string `json:"email" validate:"required,min=1,max=1000"`
	Name     string `json:"name" validate:"required,min=1,max=1000"`
	Password string `json:"password" validate:"required,min=8,max=100"`
}

type LogInBody struct {
	Email    string `json:"email" validate:"required,min=1,max=1000"`
	Password string `json:"password" validate:"required,min=8,max=100"`
}
