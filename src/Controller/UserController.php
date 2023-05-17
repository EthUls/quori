<?php

namespace App\Controller;

use App\Entity\User;
use App\Form\UserType;
use App\Services\UploadImageService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\Form\Extension\Core\Type\PasswordType;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

class UserController extends AbstractController
{
    #[Route('/user', name: 'current_user_profile')]
    #[IsGranted("IS_AUTHENTICATED_REMEMBERED")]
    public function currentUserProfil(Request $request, UserPasswordHasherInterface $passwordHasher, EntityManagerInterface $em, UploadImageService $uploaderPicture): Response
    {
        /**
         * @var User
         */
        $currentUser = $this->getUser();
        $profileForm = $this->createForm(UserType::class, $currentUser);
        $profileForm->remove('password');
        $profileForm->add('newPassword', PasswordType::class, ['label' => 'Nouveau mot de passe', 'required' => false]);

        $profileForm->handleRequest($request);

        if($profileForm->isSubmitted() && $profileForm->isValid()) {
            // Mise a jour des informations de l'utilisateur
            $newPassword = $currentUser->getNewPassword();
            if($newPassword) {
                $hashedNewPassword = $passwordHasher->hashPassword($currentUser, $newPassword);
                $currentUser->setPassword($hashedNewPassword);
            }
            $em->flush();
            $this->addFlash('success', 'Modifications des informations sauvegardées !');
        }

            $picture = $profileForm->get('pictureFile')->getData();
            if($picture) {
                $currentUser->setImage($uploaderPicture->uploadProfileImage($picture, $currentUser->getImage()));

            }

        return $this->render('user/profile.html.twig', [
            'form' => $profileForm->createView()
        ]);
    }

    #[Route('/user/questions', name: 'show_questions')]
    #[IsGranted('IS_AUTHENTICATED_REMEMBERED')]
    public function showQuestions()
    {
        return $this->render('user/show_questions.html.twig');
    }

    #[Route('/user/comments', name: 'show_comments')]
    #[IsGranted('IS_AUTHENTICATED_REMEMBERED')]
    public function showComments()
    {
        return $this->render('user/show_comments.html.twig');
    }

    #[Route('/user/{id}', name: 'profile_user')]
    #[IsGranted("IS_AUTHENTICATED_REMEMBERED")]
    public function userProfile(User $user): Response
    {
        $currentUser = $this->getUser();
        if($currentUser === $user) {
            return $this->redirectToRoute('current_user_profile');
        }

        return $this->render('user/show.html.twig', ['user' => $user]);
    }

}
