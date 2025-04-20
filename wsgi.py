from app import application

# Vercel espera que la variable se llame 'app'
app = application

if __name__ == "__main__":
    app.run()