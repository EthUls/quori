<?php

namespace App\Controller;

use App\Entity\ResetPassword;
use App\Entity\User;
use App\Form\UserType;
use App\Repository\ResetPasswordRepository;
use App\Repository\UserRepository;
use App\Services\UploadImageService;
use DateTime;
use DateTimeImmutable;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bridge\Twig\Mime\TemplatedEmail;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\Form\Extension\Core\Type\EmailType;
use Symfony\Component\Form\Extension\Core\Type\PasswordType;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;
use Symfony\Component\Security\Http\Authentication\UserAuthenticatorInterface;
use Symfony\Component\Validator\Constraints\Email;
use Symfony\Component\Validator\Constraints\Length;
use Symfony\Component\Validator\Constraints\NotBlank;

class SecurityController extends AbstractController
{

    function __construct(private $formLoginAuthenticator)
    {
        
    }

    #[Route('/signup', name: 'signup')]
    public function signup(Request $request, UserPasswordHasherInterface $passwordHasher, EntityManagerInterface $em, UserAuthenticatorInterface $userAuthenticator, MailerInterface $mailer, UploadImageService $uploaderPicture): Response
    {
        $user = new User();
        $signupForm = $this->createForm(UserType::class, $user);
        $signupForm->handleRequest($request);

        if ($signupForm->isSubmitted() && $signupForm->isValid()) {
            $hashedPassword = $passwordHasher->hashPassword($user, $user->getPassword());
            $user->setPassword($hashedPassword);

            $picture = $signupForm->get('pictureFile')->getData();
            if($picture) {
                $user->setImage($uploaderPicture->uploadProfileImage($picture));
            } else {
                $user->setImage("/profiles/default_profile.png");
            }



            $em->persist($user);
            $em->flush();

            // Envoie d'un mail de bienvenue.
            $email = new TemplatedEmail();
            $email->to($user->getEmail())
                    ->subject("Bienvenu sur Quori")
                    ->htmlTemplate('@email_templates/welcome.html.twig')
                    ->context([
                        'fullname' => $user->getFullname()
                    ]);
            $mailer->send($email);

            $this->addFlash('success', 'Bienvenue sur Quori !');
            return $userAuthenticator->authenticateUser($user, $this->formLoginAuthenticator, $request);
        }

        return $this->render('security/signup.html.twig', ['form' => $signupForm->createView()]);
    }

    #[Route('/signin', name: 'signin')]
    public function signin(AuthenticationUtils $authenticationUtils): Response
    {
        if($this->getUser()) {
            return $this->redirectToRoute('home');
        }

        $error = $authenticationUtils->getLastAuthenticationError();
        $username = $authenticationUtils->getLastUsername();

        return $this->render('security/signin.html.twig', [
            'error' => $error,
            'username' => $username
        ]);
    }

    #[Route('/logout', name: 'logout')]
    public function logout() {}

    #[Route('/reset-password-request', name: 'reset-password-request')]
    public function resetPasswordRequest(Request $request, UserRepository $userRepository, EntityManagerInterface $em, ResetPasswordRepository $resetPasswordRepository, MailerInterface $mailer, RateLimiterFactory $passwordRecoveryLimiter) {

        $limiter = $passwordRecoveryLimiter->create($request->getClientIp());
        


        $emailForm = $this->createFormBuilder()
                            ->add('email', EmailType::class, [
                                'constraints' => [
                                    new NotBlank([
                                        'message' => "Veuillez renseigner ce champ."
                                    ]),
                                    new Email([
                                        'message' => "Veuillez entrer un email valide."
                                    ])
                                ]
                            ])
                            ->getForm();

        $emailForm->handleRequest($request);

        if ($emailForm->isSubmitted() && $emailForm->isValid()) {
            if(!$limiter->consume(1)->isAccepted()){
                $this->addFlash('error', "Vous devez attendre 1 heure pour refaire une demande");
                return $this->redirectToRoute('signin');
            };
            $email = $emailForm->get('email')->getData();
            $user = $userRepository->findOneBy(['email' => $email]);

            if($user) {

                $oldResetPassword = $resetPasswordRepository->findOneBy(['user' => $user]);
                if($oldResetPassword){
                    $em->remove($oldResetPassword);
                    $em->flush();
                }

                    // + = /
                $token = substr(str_replace(['+', '/', '='], '', base64_encode(random_bytes(40))), 0, 20);

                $resetPassword = new ResetPassword();
                $resetPassword->setUser($user)
                                ->setToken(sha1($token))
                                ->setExpiredAt(new DateTimeImmutable('+2 hours'));

                $em->persist($resetPassword);
                $em->flush();

                $resetEmail = new TemplatedEmail();
                $resetEmail->to($email)
                            ->subject('Demande de réinitialisation de mot de passe')
                            ->htmlTemplate('@email_templates/reset-password-request.html.twig')
                            ->context([
                                'fullname' => $user->getFullname(),
                                'token' => $token
                            ]);
                $mailer->send($resetEmail);

                $this->addFlash('success', "Un email vous a été envoyé.");
                return $this->redirectToRoute('signin');
            } else {
                $this->addFlash('error', "Cet email n'existe pas.");
            }
                            
        }

        return $this->render('security/reset-password-request.html.twig', ['form' => $emailForm->createView()]);
    }

    #[Route('/reset-password/{token}', name: 'reset-password')]
    public function resetPassword(string $token,Request $request, ResetPasswordRepository $resetPasswordRepository, EntityManagerInterface $em, UserPasswordHasherInterface $passwordHasher, RateLimiterFactory $passwordRecoveryLimiter) {

        $limiter = $passwordRecoveryLimiter->create($request->getClientIp());
        if(!$limiter->consume(1)->isAccepted()){
            $this->addFlash('error', "Vous devez attendre 1 heure pour refaire une demande");
            return $this->redirectToRoute('signin');
        };

        // Verifier que le token est bien dans la bdd
        $resetPassword = $resetPasswordRepository->findOneBy(['token' => sha1($token)]);
        // Verifier qu'il na pas expirer
        if(!$resetPassword || $resetPassword->getExpiredAt() < new DateTime('now') ) {

            if($resetPassword) {
                $em->remove($resetPassword);
                $em->flush();
            }

            $this->addFlash('error', "Votre demande a expiré, veuillez la refaire");
            return $this->redirectToRoute('reset-password-request');
        }
        // retrouver le user
        // formulaire pour la saisie du nouveau pw
        $resetPasswordForm = $this->createFormBuilder()
                                    ->add('password', PasswordType::class, [
                                        'label' => "Nouveau mot de passe",
                                        'constraints' => [
                                            new Length([
                                                'min' => 6,
                                                'minMessage' => 'Le mot de passe doit faire au moins 6 caractères'
                                            ]),
                                            new NotBlank([
                                                'message' => 'Veuillez saisir ce champs'
                                            ])
                                        ]
                                    ])
                                    ->getForm();
        $resetPasswordForm->handleRequest($request);
        
        if($resetPasswordForm->isSubmitted() && $resetPasswordForm->isValid()) {
            // Récupération de l'USER
            $user = $resetPassword->getUser();
            // Récupération du MDP depuis le formulaire
            $newPassword = $resetPasswordForm->get('password')->getData();

            $hashedNewPassword = $passwordHasher->hashPassword($user, $newPassword);
            // mise a jour du mot de passe
            $user->setPassword($hashedNewPassword);

            // on supprime la demande de reset de la bdd
            $em->remove($resetPassword);
            $em->flush();

            $this->addFlash('success', 'Votre mot de passe a bien été mis a jour');
            return $this->redirectToRoute('signin');
        };

        return $this->render('security/reset-password-form.html.twig', ['form' => $resetPasswordForm->createView()]);
    }
}
