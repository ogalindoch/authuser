<?php

namespace euroglas\authuser;

class authuser extends \euroglas\eurorest\auth
{
	// Nombre del cliente autenticado
	private $authName = "";

    // Nombre oficial del modulo
    public function name() { return "authuser"; }

    // Descripcion del modulo
    public function description() { return "Módulo de autenticacion usando Usuario/Contraseña"; }

    // Regresa un arreglo con las rutas del modulo
    public function rutas()
    {
		$items = parent::rutas();

        $items['/auth/name']['GET'] = array(
            'name' => 'Nombre del cliente autenticado',
            'callback' => 'getAuthName',
            'token_required' => TRUE,
        );

        return $items;
    }
        /**
     * Define que secciones de configuracion requiere
     * 
     * @return array Lista de secciones requeridas
     */
    public function requiereConfig()
    {
        $secciones = array();

        // Detalles de acceso a la BD
        $secciones[] = 'dbaccess';

        // Detalles para accesar los datos del usuario
        $secciones[] = 'authuser';

        // Estos son los datos que podrían 
        // estar en la seccion de usuario:
        //
        // dbaccess = 'servidorAPI'
        // table = 'usuarios'
        // loginField = 'Nombre'
        // passwField = 'Password'

        return $secciones;
    }


    /**
     * Carga UNA seccion de configuración
     * 
     * Esta función será llamada por cada seccion que indique "requiereConfig()"
     * 
     * @param string $sectionName Nombre de la sección de configuración
     * @param array $config Arreglo con la configuracion que corresponde a la seccion indicada
     * 
     */
    public function cargaConfig($sectionName, $config)
    {
        $this->config[$sectionName] = $config;
    }

    /**
     * Inicializa la conexión a la base de datos
     * 
     * Usa los datos del archivo de configuración para hacer la conexión al Ring
     */
    private function dbInit()
    {
        // Aún es no tenemos una conexión
        if( $this->dbRing == null )
        {
            // Tenemos el nombre del archivo de configuración de dbAccess
            // print_r($this->config);
            if( isset( $this->config['dbaccess'], $this->config['dbaccess']['config'] ) )
            {
                // Inicializa DBAccess
                //print("Cargando configuracion DB: ".$this->config['dbaccess']['config']);
                $this->dbRing = new \euroglas\dbaccess\dbaccess($this->config['dbaccess']['config']);

                // Nos conectamos a la BD que indica la configuración
                if( $this->dbRing->connect($this->config['authuser']['dbaccess']) === false )
                {
                    print($this->dbRing->getLastError());
                }
            }
        }
    }

    /**
     * Parsea el token, y verifica que sea valido
	 * 
     * @param array $args Arreglo con la información necesaria para autenticar al usuario.
     * 
     * @return string El token generado para el usuario
     */
    public function auth( $args = NULL )
    {
        //print_r($args);

        // Verifica que recibimos los parametros login/password

        if( FALSE == array_key_exists("login",$args) )
        {
            header('content-type: application/json');
            http_response_code(401); // 401 Unauthorized
            die(json_encode( array(
                'codigo' => 401001,
                'mensaje' => 'No autorizado',
                'descripcion' => 'La solicitud no contenia el parametro login',
                'detalles' => $args
            )));
        }
        $testLogin = $args['login'];

        // Verifica que recibimos el password
        if( FALSE == array_key_exists("password",$args) )
        {
            header('content-type: application/json');
            http_response_code(401); // 401 Unauthorized
            die(json_encode( array(
                'codigo' => 401001,
                'mensaje' => 'No autorizado',
                'descripcion' => 'La solicitud no contenia el password requerido',
                'detalles' => $args
            )));
        }
        $testPass = $args['password'];

        // Asegura que estamos conectados a la BD
        $this->dbInit();

        $dbTable = $this->config['authuser']['table'];
        $usrField = $this->config['authuser']['loginField'];
        $passField = $this->config['authuser']['passwField'];

        $query = "SELECT {$usrField} AS login, {$passField} AS pass FROM {$dbTable} WHERE {$usrField} = '{$testLogin}'";


        $sth = $this->dbRing->query($query,\PDO::FETCH_ASSOC);
        
        if( $sth === false )
        {
            header('content-type: application/json');
            http_response_code(400); // 400 Unauthorized
            die(json_encode( array(
                'codigo' => 400101,
                'mensaje' => 'No autorizado',
                'descripcion' => $this->dbRing->getLastError(),
                'detalles' => $args
            )));
        }

        $datosDelCliente = $sth->fetch(\PDO::FETCH_ASSOC);

        if( empty( $datosDelCliente ) )
        {
            header('content-type: application/json');
            http_response_code(401); // 401 Unauthorized
            die(json_encode( array(
                'codigo' => 401003,
                'mensaje' => 'No autorizado',
                'descripcion' => 'User not found',
                'detalles' => $args
            )));
        } else {
            // print_r($datosDelCliente);
        }


        $uData = array();
        $uData['login'] = $datosDelCliente['login'];
        $uData['name'] = $datosDelCliente['login'];
        $uData['vrfy'] = 'login';

        die($this->generaToken( $uData ));
    }

    public function authFromJWT( $serializedToken )
    {

        $jwt = new \Emarref\Jwt\Jwt();
        $token = $jwt->deserialize($serializedToken);

        // Prepara la encriptacion
        $algorithm = new \Emarref\Jwt\Algorithm\Hs256($this->_Secreto);
        $encryption = \Emarref\Jwt\Encryption\Factory::create($algorithm);
        
        // Este es el contexto con el que se va a validar el Token
        $context = new \Emarref\Jwt\Verification\Context( $encryption );
        $context->setIssuer($_SERVER["SERVER_NAME"]);
		$context->setSubject('eurorest');
		$options = array();

        // Normalmente aqui usaría un try/catch,
		// pero al final de nuevo lanzaría una excepcion.
		// Mejor voy a dejar que la excepcion se propague.

        $jwt->verify($token, $context);

        // Lista los claims del token
        //$jsonPayload = $token->getPayload()->getClaims()->jsonSerialize();
        //print($jsonPayload);

	    $autoRenewClaim = $token->getPayload()->findClaimByName('Autorenew');
	    if($autoRenewClaim !== null)
	    {
	    	$options["Autorenew"] = $autoRenewClaim->getValue();
        }
        $options["Autorenew"] = true;

	    $renewTimeClaim = $token->getPayload()->findClaimByName('RTime');
	    if($renewTimeClaim !== null)
	    {
	    	$options['RTime'] = $renewTimeClaim->getValue();
        }
        
		$options['vrfy'] = null;
	    $vrfyClaim = $token->getPayload()->findClaimByName('vrfy');
	    if($vrfyClaim !== null)
	    {
	    	$options['vrfy'] = $vrfyClaim->getValue();
	    	$vrfyClaimValue = $options['vrfy'];
	    	switch ($vrfyClaimValue) {
	    		case 'key':
	    		case 'email':
	    		case 'login':
	    			// Omite las validaciones por ahora
	    			break;

	    		default:
	    			http_response_code(401); // 401 Unauthorized
	    			header('content-type: application/json');
                    die(json_encode( array(
                        'codigo' => 401111,
                        'mensaje' => 'Vrfy Code Error',
                        'descripcion' => "El codigo VRFY no es reconocido",
                        'detalles' => $vrfyClaimValue
                    )));
	    			break;
	    	}
	    }

		$options['login'] = $token->getPayload()->findClaimByName('login');

		$this->authName = $token->getPayload()->findClaimByName('name')->getValue();
		//print( 'AuthName: '.$this->authName);

	    // Autorenew debe ser el ultimo, ya que tengamos todo lo necesario en Options
	    if( isset( $options["Autorenew"] ) && $options["Autorenew"] == true )
	    {
	    	$newToken = $this->generaToken($options);
	    	//header("Access-Control-Expose-Headers","New-JWT-Token");
	    	header("Authorization: {$newToken}");
	    }
	}
	
	public function getAuthName() 
	{
		//print("AuthName Requested: ".$this->authName);
		die( $this->authName );
    }
    
    private $config = array();
	private $dbRing = null;
}
