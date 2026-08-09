# CAS Antivirus & Security Headers

A free WordPress plugin designed to protect your website against unauthorized access, malicious threats, and improve security hardening using secure HTTP headers.

## 🚀 Key Features

* **Antivirus Protection:** Scans and detects malicious code or suspicious files within your WordPress installation.
* **2FA Authentication:** Strengthens login security by adding a two-factor verification layer to protect user and administrator accounts.
* **Security Headers:** Advanced configuration to add protective HTTP headers (such as HSTS, X-Frame-Options, X-Content-Type-Options, etc.).
* **Lightweight & Optimized:** Developed to consume minimal resources and ensure it won't slow down your website.
* **100% Free and Open Source.**

## 📥 Installation

1. Download the latest version of the plugin from the [Releases](https://bueninformatico.com/wordpress/plugins/) section or clone this repository.
2. Upload the plugin folder to the `/wp-content/plugins/` directory of your WordPress installation, or compress it into a `.zip` file and upload it from your WordPress admin dashboard (*Plugins > Add New > Upload Plugin*).
3. Activate the plugin from your WordPress control panel.
4. Go to the settings menu to configure security options, 2FA, and headers according to your preferences.

## ⚙️ Requirements

* WordPress 5.0 or higher.
* PHP 7.4 or higher.

## 🤝 Contributing

Contributions, suggestions, and bug reports are always welcome! If you want to propose improvements or new features, feel free to open a *Pull Request* or an *Issue* in this repository.

## 📄 License

This project is distributed under the [MIT](LICENSE) license.


<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Burbuja GitHub</title>
    <style>
        /* Estilos para el contenedor de la burbuja */
        .github-bubble-container {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            display: inline-block;
        }

        /* Estilos principales de la burbuja */
        .github-bubble {
            display: flex;
            align-items: center;
            justify-content: center;
            text-decoration: none;
            background-color: #24292e; /* Color oscuro estilo GitHub */
            color: #ffffff;
            padding: 12px 24px;
            border-radius: 50px; /* Forma de burbuja */
            font-weight: 600;
            font-size: 14px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            transition: all 0.3s ease;
            border: 2px solid transparent;
        }

        /* Efecto al pasar el ratón (hover) */
        .github-bubble:hover {
            background-color: #2f363d; /* Un tono más claro al hacer hover */
            transform: translateY(-2px); /* Ligera elevación */
            box-shadow: 0 6px 12px rgba(0, 0, 0, 0.15);
            border-color: #ffffff; /* Borde blanco al pasar el ratón */
        }

        /* Estilo del icono de GitHub */
        .github-icon {
            margin-right: 10px;
            width: 20px;
            height: 20px;
            fill: currentColor; /* Hereda el color del texto */
        }
    </style>
</head>
<body>

<!-- El elemento de la burbuja HTML -->
<div class="github-bubble-container">
    <a href="https://github.com/soysupercas" target="_blank" class="github-bubble">
        <!-- Icono de GitHub (vector SVG) -->
        <svg class="github-icon" viewBox="0 0 16 16" version="1.1" width="16" height="16" aria-hidden="true">
            <path fill-rule="evenodd" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.22 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.28.82 2.15 0 3.06-1.86 3.75-3.64 3.95.23.2.44.55.51 1.07-.01.88-.01 1.82-.01 2.2 0 .21.15.45.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"></path>
        </svg>
        GitHub Plugin Developer
    </a>
</div>

</body>
</html>
